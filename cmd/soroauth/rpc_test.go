package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// rpcFixtures is the committed set of JSON-RPC response bodies the simulate and
// submit subcommands consume. The tests never touch the network: they drive a
// local server that answers with these bodies, so the subcommands are exercised
// through the same rpcclient path a real endpoint would use while the bytes
// they parse are fixed and reviewable.
type rpcFixtures struct {
	Note                 string          `json:"note"`
	SimulateRecord       json.RawMessage `json:"simulate_record"`
	SimulateEnforce      json.RawMessage `json:"simulate_enforce"`
	SendPending          json.RawMessage `json:"send_pending"`
	GetTransactionOK     json.RawMessage `json:"get_transaction_success"`
	GetTransactionFailed json.RawMessage `json:"get_transaction_failed"`
}

func loadRPCFixtures(t *testing.T) rpcFixtures {
	t.Helper()
	path := filepath.Join("testdata", "rpc", "responses.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var fixtures rpcFixtures
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
	return fixtures
}

// fakeRPC is a JSON-RPC endpoint that answers the four methods these
// subcommands use from the committed fixtures. It records every method it was
// asked for, so a test can assert the two-pass order rather than only the
// final output.
type fakeRPC struct {
	server *httptest.Server

	mu            sync.Mutex
	methods       []string
	authModes     []string
	submittedTx   string
	failPoll      bool
	failSend      bool
	failSimulate  string
	upgradedAuths []bool

	// beforePoll runs at the start of the getTransaction handler, which is how
	// a test observes what the caller had already printed when polling began.
	beforePoll func()
}

// stringBuffer is a buffer a test can read while the subcommand is still
// writing to it, which is what proves the hash was printed before the poll
// started. A plain bytes.Buffer would be a data race against the handler.
type stringBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *stringBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *stringBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newFakeRPC(t *testing.T, fixtures rpcFixtures) *fakeRPC {
	t.Helper()
	fake := &fakeRPC{}
	fake.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				AuthMode        string `json:"authMode"`
				UseUpgradedAuth bool   `json:"useUpgradedAuth"`
				Transaction     string `json:"transaction"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}

		fake.mu.Lock()
		fake.methods = append(fake.methods, req.Method)
		switch req.Method {
		case "simulateTransaction":
			fake.authModes = append(fake.authModes, req.Params.AuthMode)
			fake.upgradedAuths = append(fake.upgradedAuths, req.Params.UseUpgradedAuth)
		case "sendTransaction":
			fake.submittedTx = req.Params.Transaction
		}
		failPoll := fake.failPoll
		failSend := fake.failSend
		simulateError := fake.failSimulate
		fake.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		response := map[string]any{"jsonrpc": "2.0", "id": req.ID}

		switch req.Method {
		case "simulateTransaction":
			if simulateError != "" {
				response["result"] = map[string]any{"error": simulateError}
				break
			}
			if req.Params.AuthMode == "enforce" {
				response["result"] = json.RawMessage(fixtures.SimulateEnforce)
				break
			}
			response["result"] = json.RawMessage(fixtures.SimulateRecord)

		case "sendTransaction":
			if failSend {
				response["error"] = map[string]any{"code": -32000, "message": "connection reset"}
				break
			}
			response["result"] = json.RawMessage(fixtures.SendPending)

		case "getTransaction":
			if beforePoll := fake.beforePoll; beforePoll != nil {
				beforePoll()
			}
			if failPoll {
				response["result"] = json.RawMessage(fixtures.GetTransactionFailed)
				break
			}
			response["result"] = json.RawMessage(fixtures.GetTransactionOK)

		default:
			response["error"] = map[string]any{"code": -32601, "message": "unknown method " + req.Method}
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *fakeRPC) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.methods...)
}

func (f *fakeRPC) modes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.authModes...)
}

func (f *fakeRPC) upgraded() []bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]bool(nil), f.upgradedAuths...)
}

// sentTransaction is the base64 envelope that reached sendTransaction.
func (f *fakeRPC) sentTransaction() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.submittedTx
}

// testPayer is the account that pays for and sequences the envelopes these
// tests build. It is derived from a committed label like every other test key
// here, so it is reproducible and public.
func testPayer(t *testing.T) *keypair.Full {
	t.Helper()
	return vectorKeypair(t, "soroauth-rpc-test-payer")
}

func testPayerAddress(t *testing.T) string {
	t.Helper()
	return testPayer(t).Address()
}

// decodeEnvelope decodes a base64 envelope or fails the test.
func decodeEnvelope(t *testing.T, encoded string) xdr.TransactionEnvelope {
	t.Helper()
	var envelope xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(encoded, &envelope); err != nil {
		t.Fatalf("decoding the envelope: %v", err)
	}
	return envelope
}

// invokeOperation builds an invokeHostFunction operation carrying the given
// authorization entries, reusing a committed vector's invocation so no test
// hand-builds a contract address or an argument list.
func invokeOperation(t *testing.T, entries ...xdr.SorobanAuthorizationEntry) xdr.Operation {
	t.Helper()

	reference, err := decodeEntry(loadVector(t, "v2_single_testnet").UnsignedEntryXDR)
	if err != nil {
		t.Fatalf("decoding the reference entry: %v", err)
	}
	if reference.RootInvocation.Function.ContractFn == nil {
		t.Fatal("the reference entry's root invocation is not a contract call")
	}

	return xdr.Operation{Body: xdr.OperationBody{
		Type: xdr.OperationTypeInvokeHostFunction,
		InvokeHostFunctionOp: &xdr.InvokeHostFunctionOp{
			HostFunction: xdr.HostFunction{
				Type:           xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
				InvokeContract: reference.RootInvocation.Function.ContractFn,
			},
			Auth: entries,
		},
	}}
}

// envelopeWithEntries builds a base64 transaction envelope whose single
// invokeHostFunction operation carries the given entries. The payer is who pays
// and sequences; the entries authorize whoever they are addressed to, which is
// a different account in every realistic case.
func envelopeWithEntries(t *testing.T, payer, sequence string, entries ...xdr.SorobanAuthorizationEntry) string {
	t.Helper()

	var seq int64
	if _, err := fmt.Sscanf(sequence, "%d", &seq); err != nil {
		t.Fatalf("parsing the sequence %q: %v", sequence, err)
	}

	envelope := xdr.TransactionEnvelope{
		Type: xdr.EnvelopeTypeEnvelopeTypeTx,
		V1: &xdr.TransactionV1Envelope{Tx: xdr.Transaction{
			SourceAccount: xdr.MustMuxedAddress(payer),
			Fee:           xdr.Uint32(100 * (len(entries) + 1)),
			SeqNum:        xdr.SequenceNumber(seq),
			Cond:          xdr.Preconditions{Type: xdr.PreconditionTypePrecondNone},
			Memo:          xdr.Memo{Type: xdr.MemoTypeMemoNone},
			Operations:    []xdr.Operation{invokeOperation(t, entries...)},
			Ext:           xdr.TransactionExt{V: 0},
		}},
	}

	encoded, err := xdr.MarshalBase64(envelope)
	if err != nil {
		t.Fatalf("encoding the envelope: %v", err)
	}
	return encoded
}
