package readmesnippets

import (
	"context"
	"fmt"

	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// TwoPassEnforceAndAssemble backs the README's "The two-pass simulation
// requirement" section; see Quickstart's doc comment for how the snippet
// markers relate to README.md. It is never called; it exists only to be
// compiled, so the README's example cannot rot. The parameters stand in for
// values a real caller already has: the RPC client, the signed entries from
// soroauth, the operation they authorize, and the payer account.
//
// decode-allow: the base64 blob it decodes is the SorobanTransactionData in
// the response to the enforcing simulation this function just issued, not a
// caller-supplied blob, and soroauth publishes no bounded decoder for that
// type — its bound covers authorization entries and the envelopes that carry
// them.
func TwoPassEnforceAndAssemble(
	ctx context.Context,
	client interface {
		SimulateTransaction(ctx context.Context, request rpc.SimulateTransactionRequest) (rpc.SimulateTransactionResponse, error)
	},
	signed []xdr.SorobanAuthorizationEntry,
	op *txnbuild.InvokeHostFunction,
	source txnbuild.Account,
) (*txnbuild.Transaction, error) {
	// snippet:start twopass-enforce
	op.Auth = signed

	// The enforcing pass simulates a real transaction carrying the signed
	// entries, so the host can price the signatures that are actually there.
	enforceTx, err := txnbuild.NewTransaction(txnbuild.TransactionParams{
		SourceAccount:        source,
		IncrementSequenceNum: true,
		Operations:           []txnbuild.Operation{op},
		BaseFee:              txnbuild.MinBaseFee,
		Preconditions:        txnbuild.Preconditions{TimeBounds: txnbuild.NewInfiniteTimeout()},
	})
	if err != nil {
		return nil, err
	}
	encoded, err := enforceTx.Base64()
	if err != nil {
		return nil, err
	}
	sim, err := client.SimulateTransaction(ctx, rpc.SimulateTransactionRequest{
		Transaction: encoded,
		AuthMode:    rpc.AuthModeEnforce,
	})
	if err != nil {
		return nil, err
	}
	if sim.Error != "" {
		return nil, fmt.Errorf("enforcing simulation failed: %s", sim.Error)
	}

	// The Go SDK has no assembleTransaction: attach the simulated
	// SorobanTransactionData — resources and fee sized with the signed
	// entries — to the operation by hand.
	var sorobanData xdr.SorobanTransactionData
	if err := xdr.SafeUnmarshalBase64(sim.TransactionDataXDR, &sorobanData); err != nil {
		return nil, err
	}
	op.Ext = xdr.TransactionExt{V: 1, SorobanData: &sorobanData}

	assembled, err := txnbuild.NewTransaction(txnbuild.TransactionParams{
		SourceAccount:        source,
		IncrementSequenceNum: true,
		Operations:           []txnbuild.Operation{op},
		BaseFee:              txnbuild.MinBaseFee,
		Preconditions:        txnbuild.Preconditions{TimeBounds: txnbuild.NewInfiniteTimeout()},
	})
	if err != nil {
		return nil, err
	}
	// snippet:end twopass-enforce
	return assembled, nil
}
