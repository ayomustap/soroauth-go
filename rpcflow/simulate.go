package rpcflow

import (
	"context"
	"fmt"

	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// SimulatedEntry is one authorization entry a record pass returned, with the
// position it occupies in the transaction it was recorded for.
//
// The indices are the same ones soroauth.EnvelopeEntries reports for an entry
// that is already in an envelope, so a caller can line a recorded entry up with
// the signed entry that replaces it.
type SimulatedEntry struct {
	// OperationIndex is the index of the invokeHostFunction operation the
	// entry belongs to, into the inner transaction's operations for a
	// fee-bump envelope (CAP-15: a fee-bump transaction has none of its own).
	OperationIndex int
	// EntryIndex is the entry's position in that operation's auth vector.
	EntryIndex int
	// Entry is the recorded entry, exactly as the host returned it.
	Entry xdr.SorobanAuthorizationEntry
	// Arm is the credential arm the entry the host actually recorded carries,
	// read back from the entry rather than assumed from what was requested:
	// UseUpgradedAuth is best-effort, and a host on an older protocol records
	// the legacy arm whatever was asked for.
	Arm string
}

// Record is the outcome of a record-mode simulation.
type Record struct {
	// Entries is every authorization entry the host recorded, in operation
	// order and, within an operation, in the order the host returned them.
	Entries []SimulatedEntry
	// MinResourceFee is the minimum resource fee the host reported, in
	// stroops. It is the record pass's figure and is deliberately not the one
	// to submit with: the signatures do not exist yet, so this number cannot
	// cover them.
	MinResourceFee int64
	// TransactionDataXDR is the SorobanTransactionData the host reported, as
	// base64 XDR, carrying the footprint and resources for the unsigned call.
	TransactionDataXDR string
	// LatestLedger is the ledger the simulation ran against.
	LatestLedger uint32
	// EnvelopeXDR is the simulated envelope with the recorded entries attached
	// to the operation they belong to, as base64 XDR.
	//
	// The record pass answers "which addresses must authorize this call" by
	// handing back entries, not a transaction, so an envelope that carries
	// them has to be rebuilt for the next step to have anything to sign. This
	// is that envelope, and its bytes are the input envelope's plus the auth
	// vector, so signing it is signing what was simulated.
	EnvelopeXDR string
}

// RecordParams is what SimulateRecord needs.
type RecordParams struct {
	// Client is the RPC the record pass runs against.
	Client Client
	// EnvelopeXDR is the transaction to simulate, as base64 XDR.
	EnvelopeXDR string
	// UseUpgradedAuth asks the host to record the address-bound V2 arm rather
	// than the legacy one. It is best-effort — the RPC documents it as
	// silently ignored where the host cannot emit V2 — which is why Record
	// reports the arm that was actually recorded instead of the one asked for.
	UseUpgradedAuth bool
}

// SimulateRecord runs the record pass for a transaction envelope and returns
// what the host recorded.
//
// It is the first pass of the two-pass flow this package implements, on its
// own: a caller that only wants to see which addresses must authorize a call,
// without signing anything, needs this and not SignAndSubmit. Signing callers
// get it through that function instead.
//
// The envelope is decoded through the library's bounded decoder, and so is
// every entry the host returns: both are bytes from outside this program. A
// simulation the RPC refused, or one that returned no authorization entries at
// all, is an error rather than an empty result — an invocation that needs no
// authorization would not be run through this helper, so the likely cause is
// that the wrong thing was simulated, and reporting nothing would hide that.
func SimulateRecord(ctx context.Context, p RecordParams) (Record, error) {
	var record Record

	if err := ctx.Err(); err != nil {
		return record, fmt.Errorf("soroauth: simulate record: %w", err)
	}
	if p.Client == nil {
		return record, fmt.Errorf("soroauth: simulate record: Client is required")
	}
	if p.EnvelopeXDR == "" {
		return record, fmt.Errorf("soroauth: simulate record: EnvelopeXDR is required")
	}

	envelope, err := soroauth.DecodeTransactionEnvelope(p.EnvelopeXDR)
	if err != nil {
		return record, fmt.Errorf("soroauth: simulate record: %w", err)
	}
	// The envelope is checked before the RPC is asked anything, so a caller
	// cannot spend a simulation on a transaction this flow cannot complete.
	operationIndex, err := invokeOperationIndex(&envelope)
	if err != nil {
		return record, fmt.Errorf("soroauth: simulate record: %w", err)
	}

	response, err := p.Client.SimulateTransaction(ctx, rpc.SimulateTransactionRequest{
		Transaction:     p.EnvelopeXDR,
		AuthMode:        rpc.AuthModeRecord,
		UseUpgradedAuth: p.UseUpgradedAuth,
	})
	if err != nil {
		return record, fmt.Errorf("soroauth: simulate record: %w", err)
	}
	if response.Error != "" {
		// The host's own text, never paraphrased: it is the only thing that
		// says what it objected to.
		return record, fmt.Errorf("soroauth: simulate record: the rpc refused the simulation: %s", response.Error)
	}

	entries, err := recordedAuthEntries(response)
	if err != nil {
		return record, fmt.Errorf("soroauth: simulate record: %w", err)
	}

	if err := attachRecordedAuth(&envelope, operationIndex, entries); err != nil {
		return record, fmt.Errorf("soroauth: simulate record: %w", err)
	}

	record = Record{
		Entries:            make([]SimulatedEntry, 0, len(entries)),
		MinResourceFee:     response.MinResourceFee,
		TransactionDataXDR: response.TransactionDataXDR,
		LatestLedger:       response.LatestLedger,
	}
	for i, entry := range entries {
		arm, err := credentialArm(entry)
		if err != nil {
			return Record{}, fmt.Errorf("soroauth: simulate record: recorded entry %d: %w", i, err)
		}
		record.Entries = append(record.Entries, SimulatedEntry{
			OperationIndex: operationIndex,
			EntryIndex:     i,
			Entry:          entry,
			Arm:            arm,
		})
	}

	record.EnvelopeXDR, err = xdr.MarshalBase64(envelope)
	if err != nil {
		return Record{}, fmt.Errorf("soroauth: simulate record: encoding the recorded envelope: %w", err)
	}
	return record, nil
}

// invokeOperationIndex returns the index of the envelope's single
// invokeHostFunction operation.
//
// It fails closed on an envelope with no invokeHostFunction operation or with
// more than one: the two-pass flow is defined for exactly one, a second one
// cannot be reached by this RPC at all, and picking one of several silently
// would authorize a call the caller did not choose.
func invokeOperationIndex(envelope *xdr.TransactionEnvelope) (int, error) {
	inner, err := innerTransaction(envelope)
	if err != nil {
		return 0, err
	}

	index := -1
	for i := range inner.Operations {
		if inner.Operations[i].Body.Type != xdr.OperationTypeInvokeHostFunction {
			continue
		}
		if index >= 0 {
			return 0, fmt.Errorf(
				"the envelope carries more than one invokeHostFunction operation, want exactly one: %w",
				soroauth.ErrNoInvokeOperation)
		}
		index = i
	}
	if index < 0 {
		return 0, fmt.Errorf("the envelope carries no invokeHostFunction operation: %w",
			soroauth.ErrNoInvokeOperation)
	}
	if inner.Operations[index].Body.InvokeHostFunctionOp == nil {
		return 0, fmt.Errorf("operation %d: the invokeHostFunction arm is empty", index)
	}
	return index, nil
}

// attachRecordedAuth writes the recorded entries onto the operation the record
// pass was run for, so the next step of the flow has an envelope to sign.
func attachRecordedAuth(envelope *xdr.TransactionEnvelope, index int, entries []xdr.SorobanAuthorizationEntry) error {
	inner, err := innerTransaction(envelope)
	if err != nil {
		return err
	}
	if index < 0 || index >= len(inner.Operations) {
		return fmt.Errorf("operation %d is not in the envelope", index)
	}
	if inner.Operations[index].Body.InvokeHostFunctionOp == nil {
		return fmt.Errorf("operation %d: the invokeHostFunction arm is empty", index)
	}
	inner.Operations[index].Body.InvokeHostFunctionOp.Auth = entries
	return nil
}

// innerTransaction points at the transaction holding the operations: the
// envelope's own for envelope_type_tx, and the inner transaction's for a
// fee-bump envelope, which is where the invokeHostFunction operation lives
// (CAP-15).
func innerTransaction(envelope *xdr.TransactionEnvelope) (*xdr.Transaction, error) {
	switch envelope.Type {
	case xdr.EnvelopeTypeEnvelopeTypeTx:
		if envelope.V1 == nil {
			return nil, fmt.Errorf("the envelope carries no transaction")
		}
		return &envelope.V1.Tx, nil
	case xdr.EnvelopeTypeEnvelopeTypeTxFeeBump:
		if envelope.FeeBump == nil {
			return nil, fmt.Errorf("the fee-bump envelope carries no transaction")
		}
		inner := envelope.FeeBump.Tx.InnerTx
		if inner.Type != xdr.EnvelopeTypeEnvelopeTypeTx || inner.V1 == nil {
			return nil, fmt.Errorf("the fee-bump envelope's inner transaction is not a v1 transaction")
		}
		return &inner.V1.Tx, nil
	default:
		return nil, fmt.Errorf("the envelope is not a transaction envelope")
	}
}

// credentialArm reports the arm an entry actually carries, using the same
// stable names Inspect reports so the two cannot disagree.
func credentialArm(entry xdr.SorobanAuthorizationEntry) (string, error) {
	info, err := soroauth.Inspect(entry)
	if err != nil {
		return "", err
	}
	return info.CredentialType, nil
}
