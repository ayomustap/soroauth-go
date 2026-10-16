package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
	"github.com/soroauth/soroauth-go/rpcflow"
)

// signedVectorEntries returns the signed entries of a committed vector, which
// is what a caller hands to submit after signing: real entries, signed for
// testnet, with the signature the host would check.
func signedVectorEntries(t *testing.T) []xdr.SorobanAuthorizationEntry {
	t.Helper()
	entry, err := decodeEntry(loadVector(t, "v2_single_testnet").SignedEntryXDR)
	if err != nil {
		t.Fatalf("decoding the vector's signed entry: %v", err)
	}
	return []xdr.SorobanAuthorizationEntry{entry}
}

// TestSubmitRunsTheEnforcingPassThenSendsAndPolls is the acceptance test for the
// flow: exactly one enforcing simulation, then the send, then the poll.
func TestSubmitRunsTheEnforcingPassThenSendsAndPolls(t *testing.T) {
	fixtures := loadRPCFixtures(t)
	fake := newFakeRPC(t, fixtures)

	stdout, _, err := runCLIEnv(t, map[string]string{"SEED": testPayer(t).Seed()},
		"submit",
		"--entry", envelopeWithEntries(t, testPayerAddress(t), "1", signedVectorEntries(t)...),
		"--network", "testnet",
		"--secret-env", "SEED",
		"--rpc-url", fake.server.URL)
	if err != nil {
		t.Fatalf("submit returned an error: %v\nstdout: %s", err, stdout)
	}

	want := []string{"simulateTransaction", "sendTransaction", "getTransaction"}
	if got := strings.Join(fake.calls(), ","); got != strings.Join(want, ",") {
		t.Errorf("calls were %v, want %v", fake.calls(), want)
	}
	if modes := fake.modes(); len(modes) != 1 || modes[0] != "enforce" {
		t.Errorf("auth modes %v, want exactly one enforcing pass", modes)
	}

	for _, wantOut := range []string{"hash: ", "status: SUCCESS", "ledger: 4242", "arm:    address_v2"} {
		if !strings.Contains(stdout, wantOut) {
			t.Errorf("output does not contain %q:\n%s", wantOut, stdout)
		}
	}
}

// TestSubmitSubmitsTheEnforcingPasssPriceAndTheSignedEntries proves both halves
// of the two-pass rule on the way out: the transaction that reaches the network
// carries the signatures, and its resource fee is the enforcing pass's, not the
// record pass's.
func TestSubmitSubmitsTheEnforcingPasssPriceAndTheSignedEntries(t *testing.T) {
	fixtures := loadRPCFixtures(t)
	fake := newFakeRPC(t, fixtures)

	if _, _, err := runCLIEnv(t, map[string]string{"SEED": testPayer(t).Seed()},
		"submit",
		"--entry", envelopeWithEntries(t, testPayerAddress(t), "1", signedVectorEntries(t)...),
		"--network", "testnet",
		"--secret-env", "SEED",
		"--rpc-url", fake.server.URL); err != nil {
		t.Fatalf("submit returned an error: %v", err)
	}

	sent := fake.sentTransaction()
	if sent == "" {
		t.Fatal("no transaction reached sendTransaction")
	}
	envelope := decodeEnvelope(t, sent)

	v1, ok := envelope.GetV1()
	if !ok {
		t.Fatal("the submitted envelope is not a v1 transaction envelope")
	}
	if len(envelope.Signatures()) == 0 {
		t.Error("the submitted envelope carries no signature; it would be refused for a missing one")
	}

	ops := envelope.Operations()
	invoke, ok := ops[0].Body.GetInvokeHostFunctionOp()
	if !ok {
		t.Fatal("the submitted operation is not an invokeHostFunction")
	}
	if len(invoke.Auth) != 1 {
		t.Fatalf("the submitted transaction carries %d authorization entries, want 1", len(invoke.Auth))
	}
	if invoke.Auth[0].Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2 {
		t.Errorf("the submitted entry is %s, want the arm that was signed",
			invoke.Auth[0].Credentials.Type)
	}

	data, ok := v1.Tx.Ext.GetSorobanData()
	if !ok {
		t.Fatal("the submitted transaction carries no soroban data, so no resource fee was attached")
	}
	// The enforcing fixture reports a minimum of 987654, which is deliberately
	// far above the record fixture's 4321 so a fee taken from the wrong pass is
	// visible here.
	want := xdr.Int64(987654 + rpcflow.DefaultResourceFeePadding)
	if data.ResourceFee != want {
		t.Errorf("resource fee %d, want %d (the enforcing pass's 987654 plus padding); a fee near %d "+
			"would mean the record pass priced the signatures", data.ResourceFee, want, 4321)
	}
}

// TestSubmitPrintsTheHashBeforePolling is the difference between a recoverable
// and an unrecoverable timeout: the hash has to be on stdout while the poll is
// still running, not only after it returns.
func TestSubmitPrintsTheHashBeforePolling(t *testing.T) {
	fixtures := loadRPCFixtures(t)
	fake := newFakeRPC(t, fixtures)

	var stdout stringBuffer
	var hashSeenAtPoll bool
	fake.beforePoll = func() {
		hashSeenAtPoll = strings.Contains(stdout.String(), "hash: ")
	}

	var stderr stringBuffer
	err := runWithStdin([]string{
		"submit",
		"--entry", envelopeWithEntries(t, testPayerAddress(t), "1", signedVectorEntries(t)...),
		"--network", "testnet",
		"--secret-env", "SEED",
		"--rpc-url", fake.server.URL,
	}, &stdout, &stderr, func(key string) string {
		if key == "SEED" {
			return testPayer(t).Seed()
		}
		return ""
	}, strings.NewReader(""))
	if err != nil {
		t.Fatalf("submit returned an error: %v", err)
	}

	if !hashSeenAtPoll {
		t.Errorf("the hash had not been printed when the poll started, so a timeout would leave nothing to look up\nstdout: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "status: SUCCESS") {
		t.Errorf("output does not report the terminal status:\n%s", stdout.String())
	}
}

// TestSubmitReportsAFailedTransactionVerbatim proves a terminal failure exits
// non-zero and reports the host's own result, not a paraphrase of it.
func TestSubmitReportsAFailedTransactionVerbatim(t *testing.T) {
	fixtures := loadRPCFixtures(t)
	fake := newFakeRPC(t, fixtures)
	fake.failPoll = true

	stdout, _, err := runCLIEnv(t, map[string]string{"SEED": testPayer(t).Seed()},
		"submit",
		"--entry", envelopeWithEntries(t, testPayerAddress(t), "1", signedVectorEntries(t)...),
		"--network", "testnet",
		"--secret-env", "SEED",
		"--rpc-url", fake.server.URL)
	if err == nil {
		t.Fatalf("a failed transaction exited zero, printing %q", stdout)
	}
	if code := ExitCode(err); code == ExitOK {
		t.Error("a failed transaction exited with the success code")
	}
	if want := "AAAAAAAAAGT////7AAAAAA=="; !strings.Contains(stdout, want) {
		t.Errorf("stdout does not carry the host's result XDR %q verbatim:\n%s", want, stdout)
	}
	if !strings.Contains(stdout, "status: FAILED") {
		t.Errorf("stdout does not report the terminal status:\n%s", stdout)
	}
}

// TestSubmitRefusesAnUnsignedEntry: submit is where money is spent, so an entry
// that would be refused on-chain is refused here instead, naming the address.
func TestSubmitRefusesAnUnsignedEntry(t *testing.T) {
	fixtures := loadRPCFixtures(t)
	fake := newFakeRPC(t, fixtures)

	unsigned, err := decodeEntry(loadVector(t, "v2_single_testnet").UnsignedEntryXDR)
	if err != nil {
		t.Fatalf("decoding the vector's unsigned entry: %v", err)
	}
	address := vectorKeypair(t, "soroauth-vector-signer-1").Address()

	envelope := envelopeWithEntries(t, testPayerAddress(t), "1", unsigned)
	stdout, _, err := runCLIEnv(t, map[string]string{"SEED": testPayer(t).Seed()},
		"submit",
		"--entry", envelope,
		"--network", "testnet",
		"--secret-env", "SEED",
		"--rpc-url", fake.server.URL)
	if err == nil {
		t.Fatalf("an unsigned entry was submitted, printing %q", stdout)
	}
	if code := ExitCode(err); code != ExitUsageError {
		t.Errorf("exit code %d, want %d", code, ExitUsageError)
	}
	if !strings.Contains(err.Error(), address) {
		t.Errorf("error %q does not name the unsigned address %s", err, address)
	}
	if calls := fake.calls(); len(calls) != 0 {
		t.Errorf("the refusal reached the network: %v", calls)
	}

	// The override is explicit and does reach the network.
	fake2 := newFakeRPC(t, fixtures)
	if _, _, err := runCLIEnv(t, map[string]string{"SEED": testPayer(t).Seed()},
		"submit",
		"--entry", envelope,
		"--network", "testnet",
		"--secret-env", "SEED",
		"--rpc-url", fake2.server.URL,
		"--allow-unsigned"); err != nil {
		t.Fatalf("--allow-unsigned did not submit: %v", err)
	}
	if len(fake2.calls()) == 0 {
		t.Error("--allow-unsigned still did not reach the network")
	}
}

// TestSubmitJSONIsOneObjectWithTheHashOnStderr pins the --json contract: stdout
// stays a single object, and the early announcement goes to stderr so it is
// still early without corrupting the object.
func TestSubmitJSONIsOneObjectWithTheHashOnStderr(t *testing.T) {
	fixtures := loadRPCFixtures(t)
	fake := newFakeRPC(t, fixtures)

	stdout, stderr, err := runCLIEnv(t, map[string]string{"SEED": testPayer(t).Seed()},
		"submit",
		"--entry", envelopeWithEntries(t, testPayerAddress(t), "1", signedVectorEntries(t)...),
		"--network", "testnet",
		"--secret-env", "SEED",
		"--rpc-url", fake.server.URL,
		"--json")
	if err != nil {
		t.Fatalf("submit --json returned an error: %v\nstderr: %s", err, stderr)
	}

	var out struct {
		Hash   string `json:"hash"`
		Status string `json:"status"`
		Ledger uint32 `json:"ledger"`
		Arm    string `json:"arm"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("stdout is not a single JSON object: %v\noutput: %s", err, stdout)
	}
	if out.Status != "SUCCESS" || out.Ledger != 4242 {
		t.Errorf("report is status %q ledger %d, want SUCCESS at 4242", out.Status, out.Ledger)
	}
	if out.Arm != "address_v2" {
		t.Errorf("arm %q, want the arm the submitted envelope carried", out.Arm)
	}
	if out.Hash == "" {
		t.Error("the report carries no hash")
	}
	if !strings.Contains(stderr, out.Hash) {
		t.Errorf("the hash was not announced on stderr before polling: %q", stderr)
	}
	if strings.Contains(stdout, "polling") {
		t.Errorf("stdout carries the stderr announcement: %q", stdout)
	}
}

// TestSubmitJSONFailureStillCarriesTheHostsResult keeps the failure report
// machine-readable and complete.
func TestSubmitJSONFailureStillCarriesTheHostsResult(t *testing.T) {
	fixtures := loadRPCFixtures(t)
	fake := newFakeRPC(t, fixtures)
	fake.failPoll = true

	stdout, _, err := runCLIEnv(t, map[string]string{"SEED": testPayer(t).Seed()},
		"submit",
		"--entry", envelopeWithEntries(t, testPayerAddress(t), "1", signedVectorEntries(t)...),
		"--network", "testnet",
		"--secret-env", "SEED",
		"--rpc-url", fake.server.URL,
		"--json")
	if err == nil {
		t.Fatal("a failed transaction exited zero")
	}

	var out struct {
		Status      string   `json:"status"`
		ResultXDR   string   `json:"result_xdr"`
		Diagnostics []string `json:"diagnostic_events"`
		Error       string   `json:"error"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("stdout is not a JSON object: %v\noutput: %s", err, stdout)
	}
	if out.Status != "FAILED" {
		t.Errorf("status %q, want FAILED", out.Status)
	}
	if out.ResultXDR != "AAAAAAAAAGT////7AAAAAA==" {
		t.Errorf("result_xdr %q, want the host's verbatim result", out.ResultXDR)
	}
	if len(out.Diagnostics) != 1 {
		t.Errorf("got %d diagnostic events, want 1", len(out.Diagnostics))
	}
	if out.Error == "" {
		t.Error("the failure object carries no error text")
	}
}

// TestSubmitRejects covers the fail-closed input checks, none of which may reach
// the network.
func TestSubmitRejects(t *testing.T) {
	envelope := envelopeWithEntries(t, testPayerAddress(t), "1", signedVectorEntries(t)...)
	unsignedEnvelope := envelopeWithEntries(t, testPayerAddress(t), "1",
		func() xdr.SorobanAuthorizationEntry {
			entry, err := decodeEntry(loadVector(t, "v2_single_testnet").UnsignedEntryXDR)
			if err != nil {
				t.Fatalf("decoding the vector entry: %v", err)
			}
			return entry
		}())

	tests := []struct {
		name    string
		env     map[string]string
		args    []string
		wantMsg string
	}{
		{
			name:    "no entry",
			args:    []string{"submit", "--network", "testnet", "--secret-env", "SEED"},
			wantMsg: "--entry is required",
		},
		{
			name:    "no secret env",
			args:    []string{"submit", "--entry", envelope, "--network", "testnet"},
			wantMsg: "--secret-env is required",
		},
		{
			name: "no network",
			args: []string{"submit", "--entry", envelope, "--secret-env", "SEED",
				"--rpc-url", "http://rpc.invalid"},
			env:     map[string]string{"SEED": testPayer(t).Seed()},
			wantMsg: "--network is required",
		}, {
			name:    "no endpoint",
			args:    []string{"submit", "--entry", envelope, "--network", "testnet", "--secret-env", "SEED"},
			env:     map[string]string{"SEED": testPayer(t).Seed()},
			wantMsg: "SOROAUTH_RPC_URL",
		},
		{
			name: "environment variable unset",
			args: []string{"submit", "--entry", envelope, "--network", "testnet", "--secret-env", "MISSING",
				"--rpc-url", "http://rpc.invalid"},
			wantMsg: "MISSING is empty or unset",
		},
		{
			name: "environment variable holds a public key",
			env:  map[string]string{"SEED": testPayer(t).Address()},
			args: []string{"submit", "--entry", envelope, "--network", "testnet", "--secret-env", "SEED",
				"--rpc-url", "http://rpc.invalid"},
			wantMsg: "a secret seed (S…) is required",
		},
		{
			name: "not base64",
			env:  map[string]string{"SEED": testPayer(t).Seed()},
			args: []string{"submit", "--entry", "not-base64", "--network", "testnet", "--secret-env", "SEED",
				"--rpc-url", "http://rpc.invalid"},
			wantMsg: "decoding --entry as a transaction envelope",
		},
		{
			name: "an authorization entry rather than an envelope",
			env:  map[string]string{"SEED": testPayer(t).Seed()},
			args: []string{"submit", "--entry", loadVector(t, "v2_single_testnet").SignedEntryXDR,
				"--network", "testnet", "--secret-env", "SEED", "--rpc-url", "http://rpc.invalid"},
			wantMsg: "decoding --entry as a transaction envelope",
		},
		{
			name: "unknown flag",
			args: []string{"submit", "--nope"},
			// The flag package reports this before any of the checks, so the
			// message is the flag package's own.
			wantMsg: "flag provided but not defined",
		},
		{
			name: "a fee bump envelope",
			env:  map[string]string{"SEED": testPayer(t).Seed()},
			args: []string{"submit", "--entry", feeBumpEnvelopeWith(t, envelope), "--network", "testnet",
				"--secret-env", "SEED", "--rpc-url", "http://rpc.invalid"},
			wantMsg: "fee-bump envelope is not supported",
		},
		{
			name: "an unsigned entry without the override",
			env:  map[string]string{"SEED": testPayer(t).Seed()},
			args: []string{"submit", "--entry", unsignedEnvelope, "--network", "testnet",
				"--secret-env", "SEED", "--rpc-url", "http://rpc.invalid"},
			wantMsg: "is unsigned",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _, err := runCLIEnv(t, tt.env, tt.args...)
			if err == nil {
				t.Fatalf("the command succeeded, printing %q", stdout)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tt.wantMsg)
			}
			if code := ExitCode(err); code != ExitUsageError {
				t.Errorf("exit code %d, want %d", code, ExitUsageError)
			}
			if stdout != "" {
				t.Errorf("a failing command wrote to stdout: %q", stdout)
			}
		})
	}
}

// feeBumpEnvelopeWith wraps an envelope in a fee bump, the shape this command
// refuses because the account that pays is not the one it signs for.
func feeBumpEnvelopeWith(t *testing.T, inner string) string {
	t.Helper()

	feeSource, err := keypair.FromRawSeed([32]byte{9, 9, 9})
	if err != nil {
		t.Fatalf("deriving the fee source: %v", err)
	}
	envelope := decodeEnvelope(t, inner)
	wrap := xdr.TransactionEnvelope{
		Type: xdr.EnvelopeTypeEnvelopeTypeTxFeeBump,
		FeeBump: &xdr.FeeBumpTransactionEnvelope{Tx: xdr.FeeBumpTransaction{
			FeeSource: xdr.MustMuxedAddress(feeSource.Address()),
			Fee:       200,
			InnerTx: xdr.FeeBumpTransactionInnerTx{
				Type: xdr.EnvelopeTypeEnvelopeTypeTx,
				V1:   envelope.V1,
			},
			Ext: xdr.FeeBumpTransactionExt{V: 0},
		}},
	}
	encoded, err := xdr.MarshalBase64(wrap)
	if err != nil {
		t.Fatalf("encoding the fee-bump envelope: %v", err)
	}
	return encoded
}

// TestUnsignedRefusalAllowsADelegatesTopLevelVoid covers the one exception the
// refusal must not swallow: CAP-71-01 permits a Void top-level signature on a
// delegates entry when every delegate authenticates.
func TestUnsignedRefusalAllowsADelegatesTopLevelVoid(t *testing.T) {
	vector := loadVector(t, "delegates_single_node")
	entry, err := decodeEntry(vector.UnsignedEntryXDR)
	if err != nil {
		t.Fatalf("decoding the delegates vector entry: %v", err)
	}

	// Unsigned throughout: the top-level node and the delegate.
	if address := unsignedRefusal([]xdr.SorobanAuthorizationEntry{entry}, vector.NetworkPassphrase); address == "" {
		t.Error("a delegates entry with no signatures at all was accepted")
	}

	// Sign the delegate through the library, leaving the top level Void.
	signers := make([]soroauth.Signer, 0, len(vector.Delegates))
	for _, delegate := range vector.Delegates {
		signers = append(signers, soroauth.NewEd25519Signer(vectorKeypair(t, delegate.Label)))
	}
	signed, err := soroauth.AuthorizeAll(t.Context(), []xdr.SorobanAuthorizationEntry{entry},
		signers, vector.ValidUntilLedger, vector.NetworkPassphrase)
	if err != nil {
		t.Fatalf("signing the delegates entry: %v", err)
	}
	if address := unsignedRefusal(signed, vector.NetworkPassphrase); address != "" {
		t.Errorf("a delegates entry whose delegate is signed was refused for %s, "+
			"but CAP-71-01 permits the Void top-level node", address)
	}

	// A nested delegate that nothing signed is still a refusal: the exception
	// is for the top-level node, not for a hole further down.
	nested := loadVector(t, "delegates_unsorted_with_nested")
	nestedEntry, err := decodeEntry(nested.UnsignedEntryXDR)
	if err != nil {
		t.Fatalf("decoding the nested vector entry: %v", err)
	}
	nestedSigners := make([]soroauth.Signer, 0, len(nested.Delegates))
	for _, delegate := range nested.Delegates {
		nestedSigners = append(nestedSigners, soroauth.NewEd25519Signer(vectorKeypair(t, delegate.Label)))
	}
	nestedSigned, err := soroauth.AuthorizeAll(t.Context(), []xdr.SorobanAuthorizationEntry{nestedEntry},
		nestedSigners, nested.ValidUntilLedger, nested.NetworkPassphrase)
	if err != nil {
		t.Fatalf("signing the nested delegates entry: %v", err)
	}
	if address := unsignedRefusal(nestedSigned, nested.NetworkPassphrase); address == "" {
		t.Error("a delegates entry with an unsigned nested delegate was accepted")
	}
}
