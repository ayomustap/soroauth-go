package rpcflow

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// recordedEntryOfArm builds the unsigned entry a record pass returns for the
// given signer on the given credential arm. A test uses it to prove the arm the
// host recorded is read back out of the response rather than assumed from what
// was asked for.
func recordedEntryOfArm(t testing.TB, signer string, arm xdr.SorobanCredentialsType) string {
	t.Helper()
	address, err := soroauth.ParseAddress(signer)
	if err != nil {
		t.Fatalf("parsing %q: %v", signer, err)
	}
	var contractID xdr.ContractId
	for i := range contractID {
		contractID[i] = byte(i)
	}

	credentials := xdr.SorobanCredentials{Type: arm}
	credentialsStruct := &xdr.SorobanAddressCredentials{
		Address:   address,
		Nonce:     7,
		Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid},
	}
	switch arm {
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		credentials.Address = credentialsStruct
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		credentials.AddressV2 = credentialsStruct
	default:
		t.Fatalf("unsupported arm %s in this fixture", arm)
	}

	entry := xdr.SorobanAuthorizationEntry{
		Credentials: credentials,
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &contractID},
					FunctionName:    xdr.ScSymbol("transfer"),
				},
			},
		},
	}
	encoded, err := xdr.MarshalBase64(entry)
	if err != nil {
		t.Fatalf("encoding the recorded entry: %v", err)
	}
	return encoded
}

// envelopeWithInvoke builds a base64 envelope carrying one invokeHostFunction
// operation with no authorization entries, which is what a record pass is
// given.
func envelopeWithInvoke(t testing.TB) string {
	t.Helper()
	payer := testKeypair(t, "rpcflow-payer")
	var contractID xdr.ContractId
	for i := range contractID {
		contractID[i] = byte(i)
	}
	tx, err := txnbuild.NewTransaction(txnbuild.TransactionParams{
		SourceAccount: &txnbuild.SimpleAccount{AccountID: payer.Address(), Sequence: 1},
		Operations: []txnbuild.Operation{&txnbuild.InvokeHostFunction{
			HostFunction: xdr.HostFunction{
				Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
				InvokeContract: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &contractID},
					FunctionName:    xdr.ScSymbol("transfer"),
				},
			},
			SourceAccount: payer.Address(),
		}},
		BaseFee:       txnbuild.MinBaseFee,
		Preconditions: txnbuild.Preconditions{TimeBounds: txnbuild.NewInfiniteTimeout()},
	})
	if err != nil {
		t.Fatalf("building the envelope: %v", err)
	}
	encoded, err := tx.Base64()
	if err != nil {
		t.Fatalf("encoding the envelope: %v", err)
	}
	return encoded
}

// TestSimulateRecordParsesTheRecordedPass is the property the subcommand needs:
// every entry the host recorded comes back with its position, its arm and the
// envelope it belongs to rebuilt around it.
func TestSimulateRecordParsesTheRecordedPass(t *testing.T) {
	signer := testKeypair(t, "rpcflow-signer")
	client := &fakeClient{
		simulations: []rpc.SimulateTransactionResponse{
			simResponse(t, 4321,
				recordedEntryOfArm(t, signer.Address(), xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2),
				recordedEntryOfArm(t, signer.Address(), xdr.SorobanCredentialsTypeSorobanCredentialsAddress)),
		},
		latest: 999,
	}
	// The record pass reports the ledger it ran against; the fake answers
	// getLatestLedger separately, so set the response field the host would.
	client.simulations[0].LatestLedger = 1234

	envelope := envelopeWithInvoke(t)
	record, err := SimulateRecord(context.Background(), RecordParams{Client: client, EnvelopeXDR: envelope})
	if err != nil {
		t.Fatalf("SimulateRecord returned an unexpected error: %v", err)
	}

	if len(record.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(record.Entries))
	}
	wantArms := []string{"address_v2", "address"}
	for i, entry := range record.Entries {
		if entry.OperationIndex != 0 {
			t.Errorf("entry %d operation index %d, want 0", i, entry.OperationIndex)
		}
		if entry.EntryIndex != i {
			t.Errorf("entry %d entry index %d, want %d", i, entry.EntryIndex, i)
		}
		if entry.Arm != wantArms[i] {
			t.Errorf("entry %d arm %q, want %q (the arm must be decoded from the response)", i, entry.Arm, wantArms[i])
		}
	}

	if record.MinResourceFee != 4321 {
		t.Errorf("min resource fee %d, want 4321", record.MinResourceFee)
	}
	if record.LatestLedger != 1234 {
		t.Errorf("latest ledger %d, want 1234", record.LatestLedger)
	}
	if record.TransactionDataXDR == "" {
		t.Error("no transaction data was reported")
	}

	// The recorded envelope must carry the recorded entries on the operation,
	// or the next step has nothing to sign.
	var rebuilt xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(record.EnvelopeXDR, &rebuilt); err != nil {
		t.Fatalf("decoding the recorded envelope: %v", err)
	}
	ops := rebuilt.Operations()
	if len(ops) != 1 {
		t.Fatalf("the recorded envelope carries %d operations, want 1", len(ops))
	}
	invoke, ok := ops[0].Body.GetInvokeHostFunctionOp()
	if !ok {
		t.Fatal("the recorded envelope's operation is not an invokeHostFunction")
	}
	if len(invoke.Auth) != 2 {
		t.Fatalf("the recorded envelope carries %d authorization entries, want 2", len(invoke.Auth))
	}
	if invoke.Auth[0].Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2 {
		t.Errorf("the recorded envelope's first entry is %s, want the V2 arm",
			invoke.Auth[0].Credentials.Type)
	}

	// The pass must have been the record one, and the request must carry the
	// envelope it was given.
	if len(client.authModes) != 1 || client.authModes[0] != rpc.AuthModeRecord {
		t.Errorf("auth modes %v, want exactly one record pass", client.authModes)
	}
	if !strings.Contains(client.calls[0], "simulate:"+rpc.AuthModeRecord) {
		t.Errorf("calls %v do not begin with the record pass", client.calls)
	}
}

// TestSimulateRecordRequestsUpgradedAuthWhenAsked pins the flag through to the
// request and proves the arm reported is still the recorded one: UseUpgradedAuth
// is best-effort, so a host that recorded the legacy arm must be reported that
// way even when V2 was asked for.
func TestSimulateRecordRequestsUpgradedAuthWhenAsked(t *testing.T) {
	signer := testKeypair(t, "rpcflow-signer")
	client := &fakeClient{
		simulations: []rpc.SimulateTransactionResponse{
			simResponse(t, 100,
				recordedEntryOfArm(t, signer.Address(), xdr.SorobanCredentialsTypeSorobanCredentialsAddress)),
		},
	}

	record, err := SimulateRecord(context.Background(), RecordParams{
		Client:          client,
		EnvelopeXDR:     envelopeWithInvoke(t),
		UseUpgradedAuth: true,
	})
	if err != nil {
		t.Fatalf("SimulateRecord returned an unexpected error: %v", err)
	}

	if !client.upgradedAuth[0] {
		t.Error("UseUpgradedAuth was not carried on the request")
	}
	if got := record.Entries[0].Arm; got != "address" {
		t.Errorf("arm %q, want the legacy arm the host actually recorded", got)
	}
}

// TestSimulateRecordReportsTheHostErrorVerbatim proves a refused simulation is
// reported with the host's own text, which is the only thing that says what it
// objected to.
func TestSimulateRecordReportsTheHostErrorVerbatim(t *testing.T) {
	const hostError = "HostError: Error(WasmVm, InvalidAction) at contract 0x1"
	client := &fakeClient{
		simulations: []rpc.SimulateTransactionResponse{{Error: hostError}},
	}

	_, err := SimulateRecord(context.Background(), RecordParams{
		Client:      client,
		EnvelopeXDR: envelopeWithInvoke(t),
	})
	if err == nil {
		t.Fatal("a refused simulation was accepted")
	}
	if !strings.Contains(err.Error(), hostError) {
		t.Errorf("error %q does not carry the host's own message %q", err, hostError)
	}
}

// TestSimulateRecordRejectsMissingRequirements covers the fail-closed input
// checks: nothing should reach the RPC before they pass.
func TestSimulateRecordRejectsMissingRequirements(t *testing.T) {
	tests := []struct {
		name   string
		params RecordParams
		want   string
	}{
		{"no client", RecordParams{EnvelopeXDR: "AAAA"}, "Client is required"},
		{"no envelope", RecordParams{Client: &fakeClient{}}, "EnvelopeXDR is required"},
		{
			"malformed envelope",
			RecordParams{Client: &fakeClient{}, EnvelopeXDR: "not-base64"},
			"decode transaction envelope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SimulateRecord(context.Background(), tt.params)
			if err == nil {
				t.Fatalf("SimulateRecord accepted %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not name %q", err, tt.want)
			}
			if client, ok := tt.params.Client.(*fakeClient); ok && len(client.calls) != 0 {
				t.Errorf("%s reached the RPC: %v", tt.name, client.calls)
			}
		})
	}
}

// TestSimulateRecordRefusesASimulationWithNoEntries is the fail-closed reading:
// printing nothing would hide that the wrong thing was simulated.
func TestSimulateRecordRefusesASimulationWithNoEntries(t *testing.T) {
	client := &fakeClient{
		simulations: []rpc.SimulateTransactionResponse{{Results: []rpc.SimulateHostFunctionResult{{AuthXDR: nil}}}},
	}

	_, err := SimulateRecord(context.Background(), RecordParams{
		Client:      client,
		EnvelopeXDR: envelopeWithInvoke(t),
	})
	if err == nil {
		t.Fatal("a simulation that recorded no authorization entries was accepted")
	}
	if !errors.Is(err, soroauth.ErrNoInvokeOperation) {
		t.Errorf("error %v does not wrap ErrNoInvokeOperation", err)
	}
}

// TestSimulateRecordRefusesAnEnvelopeWithNothingToAuthorize proves the envelope
// is checked before the RPC is asked anything, so a caller cannot spend a
// simulation on a transaction this flow cannot complete.
func TestSimulateRecordRefusesAnEnvelopeWithNothingToAuthorize(t *testing.T) {
	client := &fakeClient{}
	_, err := SimulateRecord(context.Background(), RecordParams{
		Client:      client,
		EnvelopeXDR: paymentOnlyEnvelope(t),
	})
	if err == nil {
		t.Fatal("an envelope with no invokeHostFunction operation was accepted")
	}
	if !errors.Is(err, soroauth.ErrNoInvokeOperation) {
		t.Errorf("error %v does not wrap ErrNoInvokeOperation", err)
	}
	if len(client.calls) != 0 {
		t.Errorf("the RPC was reached before the envelope was checked: %v", client.calls)
	}
}

// TestSimulateRecordHonoursContextCancellation asserts a cancelled context
// fails closed before the RPC is touched, as every context-taking function in
// this module does.
func TestSimulateRecordHonoursContextCancellation(t *testing.T) {
	client := &fakeClient{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := SimulateRecord(ctx, RecordParams{Client: client, EnvelopeXDR: envelopeWithInvoke(t)})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v does not wrap context.Canceled", err)
	}
	if len(client.calls) != 0 {
		t.Errorf("a cancelled call reached the RPC: %v", client.calls)
	}
}

// paymentOnlyEnvelope builds a transaction that carries no invokeHostFunction
// operation, the shape a record pass cannot be run for.
func paymentOnlyEnvelope(t testing.TB) string {
	t.Helper()
	payer := testKeypair(t, "rpcflow-payer")
	tx, err := txnbuild.NewTransaction(txnbuild.TransactionParams{
		SourceAccount: &txnbuild.SimpleAccount{AccountID: payer.Address(), Sequence: 1},
		Operations: []txnbuild.Operation{&txnbuild.Payment{
			Destination: testKeypair(t, "rpcflow-recipient").Address(),
			Asset:       txnbuild.NativeAsset{},
			Amount:      "1",
		}},
		BaseFee:       txnbuild.MinBaseFee,
		Preconditions: txnbuild.Preconditions{TimeBounds: txnbuild.NewInfiniteTimeout()},
	})
	if err != nil {
		t.Fatalf("building the envelope: %v", err)
	}
	encoded, err := tx.Base64()
	if err != nil {
		t.Fatalf("encoding the envelope: %v", err)
	}
	return encoded
}

// submitParams builds SubmitParams for the fake client, with the same source
// account and operation testParams uses.
func submitParams(t testing.TB, client Client, entries ...xdr.SorobanAuthorizationEntry) SubmitParams {
	t.Helper()
	base := testParams(t, client)
	return SubmitParams{
		Source:            base.Source,
		Operation:         base.Operation,
		Entries:           entries,
		EnvelopeSigners:   base.EnvelopeSigners,
		NetworkPassphrase: base.NetworkPassphrase,
		Client:            client,
	}
}

// signedEntryFor signs the unsigned entry a record pass would have returned
// for kp's address, so Submit is handed the kind of entry the sign subcommand
// produces rather than a hand-built stand-in.
func signedEntryFor(t testing.TB, kp *keypair.Full) xdr.SorobanAuthorizationEntry {
	t.Helper()
	unsigned, err := soroauth.DecodeAuthorizationEntry(recordedEntry(t, kp.Address()))
	if err != nil {
		t.Fatalf("decoding the recorded entry: %v", err)
	}
	signed, err := soroauth.AuthorizeEntry(context.Background(), unsigned,
		soroauth.NewEd25519Signer(kp), 1234567, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("signing the recorded entry: %v", err)
	}
	return signed
}

// TestSubmitRunsOnlyTheEnforcingPass proves the exposed tail does not repeat
// the record pass: a caller that signed its entries elsewhere already knows
// what to sign, and re-recording would discard the signatures.
func TestSubmitRunsOnlyTheEnforcingPass(t *testing.T) {
	signer := testKeypair(t, "rpcflow-signer")
	client := &fakeClient{
		simulations: []rpc.SimulateTransactionResponse{simResponse(t, 5000)},
	}

	sub, err := Submit(context.Background(), submitParams(t, client, signedEntryFor(t, signer)))
	if err != nil {
		t.Fatalf("Submit returned an unexpected error: %v", err)
	}

	want := []string{"simulate:" + rpc.AuthModeEnforce, "send", "poll"}
	if strings.Join(client.calls, ",") != strings.Join(want, ",") {
		t.Errorf("call order was %v, want %v", client.calls, want)
	}
	if sub.Status != rpc.TransactionStatusSuccess {
		t.Errorf("status %q, want %q", sub.Status, rpc.TransactionStatusSuccess)
	}
}

// TestSubmitWithoutTheEnforcingPassWouldUnderprice is the reason the two-pass
// rule exists, stated as a test: the submitted fee must come from the enforcing
// pass, not from a record pass or from the entry's own resources.
func TestSubmitUsesTheEnforcingPasssResources(t *testing.T) {
	signer := testKeypair(t, "rpcflow-signer")
	client := &fakeClient{
		simulations: []rpc.SimulateTransactionResponse{
			simResponse(t, 7000, recordedEntry(t, signer.Address())),
		},
	}

	if _, err := Submit(context.Background(), submitParams(t, client, signedEntryFor(t, signer))); err != nil {
		t.Fatalf("Submit returned an unexpected error: %v", err)
	}

	// The enforcing pass must carry the signed entries: without them it would
	// price a transaction that is not the one being submitted.
	if client.authCounts[0] != 1 {
		t.Errorf("the enforcing pass carried %d authorization entries, want 1", client.authCounts[0])
	}

	var envelope xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(client.sentEnvelope, &envelope); err != nil {
		t.Fatalf("decoding the submitted envelope: %v", err)
	}
	v1, ok := envelope.GetV1()
	if !ok {
		t.Fatal("the submitted envelope is not a v1 transaction envelope")
	}
	data, ok := v1.Tx.Ext.GetSorobanData()
	if !ok {
		t.Fatal("the submitted transaction carries no soroban data, so no resource fee was attached")
	}
	if want := xdr.Int64(7000 + DefaultResourceFeePadding); data.ResourceFee != want {
		t.Errorf("resource fee %d, want %d (the enforcing pass's 7000 plus padding)", data.ResourceFee, want)
	}
}

// TestSubmitAnnouncesTheHashBeforePolling covers the recoverable-timeout
// requirement: the hash has to reach the caller while the transaction can
// still be looked up, so OnSent must fire before PollTransaction is called.
func TestSubmitAnnouncesTheHashBeforePolling(t *testing.T) {
	signer := testKeypair(t, "rpcflow-signer")
	client := &fakeClient{
		simulations: []rpc.SimulateTransactionResponse{simResponse(t, 5000)},
	}

	var announced []Submission
	var callsAtAnnounce []string
	params := submitParams(t, client, signedEntryFor(t, signer))
	params.OnSent = func(sub Submission) {
		announced = append(announced, sub)
		callsAtAnnounce = append(callsAtAnnounce, strings.Join(client.calls, ","))
	}

	if _, err := Submit(context.Background(), params); err != nil {
		t.Fatalf("Submit returned an unexpected error: %v", err)
	}

	if len(announced) != 1 {
		t.Fatalf("OnSent was called %d times, want 1", len(announced))
	}
	if announced[0].Hash == "" {
		t.Error("OnSent received no hash, so there was nothing to look up")
	}
	if announced[0].Ledger != 0 {
		t.Errorf("OnSent received ledger %d; it runs before polling, so it cannot know one", announced[0].Ledger)
	}
	if len(callsAtAnnounce) != 1 || strings.Contains(callsAtAnnounce[0], "poll") {
		t.Errorf("OnSent ran after polling started: calls were %v", callsAtAnnounce)
	}
}

// TestSubmitDoesNotAnnounceWhenTheRPCRefusesTheSend keeps the hook honest: a
// transaction the RPC never accepted has no hash worth publishing as live.
func TestSubmitDoesNotAnnounceWhenTheRPCRefusesTheSend(t *testing.T) {
	signer := testKeypair(t, "rpcflow-signer")
	client := &fakeClient{
		simulations: []rpc.SimulateTransactionResponse{simResponse(t, 5000)},
		sendErr:     errors.New("connection reset"),
	}

	var announced int
	params := submitParams(t, client, signedEntryFor(t, signer))
	params.OnSent = func(Submission) { announced++ }

	_, err := Submit(context.Background(), params)
	if err == nil {
		t.Fatal("a failed send was reported as a successful submission")
	}
	if announced != 0 {
		t.Errorf("OnSent was called %d times for a send that failed", announced)
	}
}

// TestSubmitReportsAnOnChainRejection proves a host refusal is an outcome
// rather than a transport failure, with the host's own text intact.
func TestSubmitReportsAnOnChainRejection(t *testing.T) {
	signer := testKeypair(t, "rpcflow-signer")
	client := &fakeClient{
		simulations: []rpc.SimulateTransactionResponse{simResponse(t, 5000)},
		pollStatus:  "FAILED",
	}

	sub, err := Submit(context.Background(), submitParams(t, client, signedEntryFor(t, signer)))
	if err != nil {
		t.Fatalf("an on-chain rejection was reported as a call failure: %v", err)
	}
	if sub.Status != "FAILED" {
		t.Errorf("status %q, want FAILED", sub.Status)
	}
	if sub.Hash == "" {
		t.Error("a rejected submission reported no hash, so it cannot be looked up")
	}
}

// TestSubmitRejectsMissingRequirements keeps the fail-closed validation in
// front of the RPC on the shared tail too.
func TestSubmitRejectsMissingRequirements(t *testing.T) {
	base := submitParams(t, &fakeClient{})
	tests := []struct {
		name   string
		mutate func(*SubmitParams)
		want   string
	}{
		{"no source", func(p *SubmitParams) { p.Source = nil }, "Source"},
		{"no client", func(p *SubmitParams) { p.Client = nil }, "Client"},
		{"no passphrase", func(p *SubmitParams) { p.NetworkPassphrase = "" }, "NetworkPassphrase"},
		{"no envelope signer", func(p *SubmitParams) { p.EnvelopeSigners = nil }, "EnvelopeSigner"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := base
			params.Source = &txnbuild.SimpleAccount{AccountID: testKeypair(t, "rpcflow-payer").Address(), Sequence: 2}
			params.Client = &fakeClient{}
			client := params.Client.(*fakeClient)
			tt.mutate(&params)

			_, err := Submit(context.Background(), params)
			if err == nil {
				t.Fatalf("Submit accepted a call with %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not name %s", err, tt.want)
			}
			if len(client.calls) != 0 {
				t.Errorf("it reached the network before validating: %v", client.calls)
			}
		})
	}
}

// TestSubmitHonoursContextCancellation asserts a cancelled context fails closed
// before the enforcing pass runs.
func TestSubmitHonoursContextCancellation(t *testing.T) {
	signer := testKeypair(t, "rpcflow-signer")
	client := &fakeClient{
		simulations: []rpc.SimulateTransactionResponse{simResponse(t, 5000)},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Submit(ctx, submitParams(t, client, signedEntryFor(t, signer)))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v does not wrap context.Canceled", err)
	}
	if len(client.calls) != 0 {
		t.Errorf("a cancelled call reached the RPC: %v", client.calls)
	}
}

// transactionWith builds an in-memory envelope around the given operations.
// The tests that exercise the envelope-walking helpers build the struct
// directly rather than marshalling it, because the shapes they need — a v0
// envelope, a fee bump whose inner transaction is not v1 — are ones this
// codebase never writes.
func transactionWith(t testing.TB, ops ...xdr.Operation) xdr.TransactionEnvelope {
	t.Helper()
	payer := xdr.MustMuxedAddress(testKeypair(t, "rpcflow-payer").Address())
	return xdr.TransactionEnvelope{
		Type: xdr.EnvelopeTypeEnvelopeTypeTx,
		V1: &xdr.TransactionV1Envelope{Tx: xdr.Transaction{
			SourceAccount: payer,
			Operations:    ops,
			Cond:          xdr.Preconditions{Type: xdr.PreconditionTypePrecondNone},
			Memo:          xdr.Memo{Type: xdr.MemoTypeMemoNone},
		}},
	}
}

// invokeOp builds an invokeHostFunction operation with a valid host function.
func invokeOp(t testing.TB) xdr.Operation {
	t.Helper()
	var contractID xdr.ContractId
	for i := range contractID {
		contractID[i] = byte(i)
	}
	return xdr.Operation{Body: xdr.OperationBody{
		Type: xdr.OperationTypeInvokeHostFunction,
		InvokeHostFunctionOp: &xdr.InvokeHostFunctionOp{
			HostFunction: xdr.HostFunction{
				Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
				InvokeContract: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &contractID},
					FunctionName:    xdr.ScSymbol("transfer"),
				},
			},
		},
	}}
}

// TestInvokeOperationIndexRefusesEnvelopesItCannotUse covers every shape the
// walk refuses. Each one is a fail-closed guard: the two-pass flow is defined
// for exactly one invokeHostFunction operation, and guessing which one a caller
// meant would authorize a call they did not choose.
func TestInvokeOperationIndexRefusesEnvelopesItCannotUse(t *testing.T) {
	twoInvokes := transactionWith(t, invokeOp(t), invokeOp(t))

	emptyArm := transactionWith(t, xdr.Operation{Body: xdr.OperationBody{
		Type:                 xdr.OperationTypeInvokeHostFunction,
		InvokeHostFunctionOp: nil,
	}})

	nonV1Inner := xdr.TransactionEnvelope{
		Type: xdr.EnvelopeTypeEnvelopeTypeTxFeeBump,
		FeeBump: &xdr.FeeBumpTransactionEnvelope{Tx: xdr.FeeBumpTransaction{
			InnerTx: xdr.FeeBumpTransactionInnerTx{Type: xdr.EnvelopeTypeEnvelopeTypeTxV0},
		}},
	}

	tests := []struct {
		name     string
		envelope xdr.TransactionEnvelope
		want     string
	}{
		{
			name:     "v0 envelope",
			envelope: xdr.TransactionEnvelope{Type: xdr.EnvelopeTypeEnvelopeTypeTxV0, V0: &xdr.TransactionV0Envelope{}},
			want:     "is not a transaction envelope",
		},
		{
			name:     "tx envelope with no transaction",
			envelope: xdr.TransactionEnvelope{Type: xdr.EnvelopeTypeEnvelopeTypeTx},
			want:     "carries no transaction",
		},
		{
			name:     "fee bump with no transaction",
			envelope: xdr.TransactionEnvelope{Type: xdr.EnvelopeTypeEnvelopeTypeTxFeeBump},
			want:     "fee-bump envelope carries no transaction",
		},
		{
			name:     "fee bump whose inner transaction is not v1",
			envelope: nonV1Inner,
			want:     "inner transaction is not a v1 transaction",
		},
		{
			name:     "no invoke operation",
			envelope: transactionWith(t),
			want:     "carries no invokeHostFunction operation",
		},
		{
			name:     "two invoke operations",
			envelope: twoInvokes,
			want:     "more than one invokeHostFunction operation",
		},
		{
			name:     "empty invoke arm",
			envelope: emptyArm,
			want:     "the invokeHostFunction arm is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			index, err := invokeOperationIndex(&tt.envelope)
			if err == nil {
				t.Fatalf("accepted the envelope, returning index %d", index)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not mention %q", err, tt.want)
			}
		})
	}

	// The guards that are not the envelope's shape but the caller's index.
	oneInvoke := transactionWith(t, invokeOp(t))
	if err := attachRecordedAuth(&oneInvoke, 5, nil); err == nil {
		t.Error("attachRecordedAuth accepted an index outside the envelope")
	}
	if err := attachRecordedAuth(&emptyArm, 0, nil); err == nil {
		t.Error("attachRecordedAuth accepted an operation with no invokeHostFunction arm")
	}
	var noTransaction xdr.TransactionEnvelope
	if err := attachRecordedAuth(&noTransaction, 0, nil); err == nil {
		t.Error("attachRecordedAuth accepted an envelope it cannot read")
	}
}

// TestSimulateRecordReadsThroughAFeeBumpEnvelope covers CAP-15: the operation
// and its entries live in the inner transaction, so that is where the recorded
// entries are attached and what the reported index counts.
func TestSimulateRecordReadsThroughAFeeBumpEnvelope(t *testing.T) {
	signer := testKeypair(t, "rpcflow-signer")
	client := &fakeClient{
		simulations: []rpc.SimulateTransactionResponse{
			simResponse(t, 100, recordedEntry(t, signer.Address())),
		},
	}

	inner := transactionWith(t, invokeOp(t))
	feeBump := xdr.TransactionEnvelope{
		Type: xdr.EnvelopeTypeEnvelopeTypeTxFeeBump,
		FeeBump: &xdr.FeeBumpTransactionEnvelope{Tx: xdr.FeeBumpTransaction{
			FeeSource: xdr.MustMuxedAddress(testKeypair(t, "rpcflow-fee-source").Address()),
			Fee:       200,
			InnerTx: xdr.FeeBumpTransactionInnerTx{
				Type: xdr.EnvelopeTypeEnvelopeTypeTx,
				V1:   inner.V1,
			},
		}},
	}
	encoded, err := xdr.MarshalBase64(feeBump)
	if err != nil {
		t.Fatalf("encoding the fee-bump envelope: %v", err)
	}

	record, err := SimulateRecord(context.Background(), RecordParams{Client: client, EnvelopeXDR: encoded})
	if err != nil {
		t.Fatalf("SimulateRecord returned an unexpected error: %v", err)
	}
	if len(record.Entries) != 1 || record.Entries[0].OperationIndex != 0 {
		t.Fatalf("entries %+v, want one entry at operation 0", record.Entries)
	}

	// The recorded envelope must be a fee bump whose inner transaction carries
	// the entry, since that is the envelope the host will read.
	rebuilt, err := soroauth.DecodeTransactionEnvelope(record.EnvelopeXDR)
	if err != nil {
		t.Fatalf("decoding the recorded envelope: %v", err)
	}
	if rebuilt.Type != xdr.EnvelopeTypeEnvelopeTypeTxFeeBump {
		t.Fatalf("the recorded envelope is %s, want a fee bump", rebuilt.Type)
	}
	innerOps := rebuilt.FeeBump.Tx.InnerTx.V1.Tx.Operations
	if len(innerOps) != 1 || innerOps[0].Body.InvokeHostFunctionOp == nil {
		t.Fatal("the inner transaction lost its invokeHostFunction operation")
	}
	if got := len(innerOps[0].Body.InvokeHostFunctionOp.Auth); got != 1 {
		t.Errorf("the inner transaction carries %d entries, want 1", got)
	}
}

// TestSimulateRecordRejectsAnEnvelopeWithMoreThanOneInvoke proves the check
// runs before the RPC, so an envelope this flow cannot complete costs nothing.
func TestSimulateRecordRejectsAnEnvelopeWithMoreThanOneInvoke(t *testing.T) {
	client := &fakeClient{}
	envelope := transactionWith(t, invokeOp(t), invokeOp(t))
	encoded, err := xdr.MarshalBase64(envelope)
	if err != nil {
		t.Fatalf("encoding the envelope: %v", err)
	}

	_, err = SimulateRecord(context.Background(), RecordParams{Client: client, EnvelopeXDR: encoded})
	if err == nil {
		t.Fatal("an envelope with two invoke operations was accepted")
	}
	if !errors.Is(err, soroauth.ErrNoInvokeOperation) {
		t.Errorf("error %v does not wrap ErrNoInvokeOperation", err)
	}
	if len(client.calls) != 0 {
		t.Errorf("the RPC was reached before the envelope was checked: %v", client.calls)
	}
}
