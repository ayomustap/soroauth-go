// Package readmesnippets holds the real, compiling source the README's Go
// examples are extracted from verbatim.
//
// The region between a "// snippet:start <name>" and "// snippet:end <name>"
// comment pair is exactly what appears inside the matching fenced code block
// in README.md — TestReadmeSnippetsMatchTheirSource (readme_test.go, at the
// repository root) asserts that byte-for-byte. This file is otherwise an
// ordinary Go source file with no build tag, so `go build ./...` and
// `go vet ./...`, which CI already runs on every push, compile it like any
// other package. A snippet that stops compiling, or a README edit that lets
// the displayed code drift from what actually runs, fails the build and
// names the file — rather than being discovered by a reader running stale
// code, which is the problem this package exists to prevent.
package readmesnippets

import (
	"context"

	"github.com/stellar/go-stellar-sdk/clients/rpcclient"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// Quickstart is never called; it exists only to be compiled and to back the
// README's "Quickstart" section. Its parameters stand in for the values a
// real caller already has in hand — an RPC client, the encoded transaction
// simulation was run against, the account authorizing it, and the operation
// being assembled.
func Quickstart(ctx context.Context, client *rpcclient.Client, encodedTx string, sender *keypair.Full, op *txnbuild.InvokeHostFunction) error {
	// snippet:start quickstart
	sim, err := client.SimulateTransaction(ctx, rpc.SimulateTransactionRequest{
		Transaction: encodedTx,
		AuthMode:    rpc.AuthModeRecord,
	})
	if err != nil {
		return err
	}

	entries := make([]xdr.SorobanAuthorizationEntry, 0, len(*sim.Results[0].AuthXDR))
	for _, encoded := range *sim.Results[0].AuthXDR {
		// Simulated entries are untrusted input, so decode them through the
		// library's bounded decoder rather than the SDK's default.
		entry, err := soroauth.DecodeAuthorizationEntry(encoded)
		if err != nil {
			return err
		}
		entries = append(entries, entry)
	}

	ledger, err := client.GetLatestLedger(ctx)
	if err != nil {
		return err
	}
	validUntil, err := soroauth.ExpirationAfter(ledger.Sequence, 1000)
	if err != nil {
		return err
	}

	signed, err := soroauth.AuthorizeAll(ctx, entries,
		[]soroauth.Signer{soroauth.NewEd25519Signer(sender)},
		validUntil, network.TestNetworkPassphrase)
	if err != nil {
		return err // nothing partial is ever returned
	}

	op.Auth = signed // then re-simulate in enforce mode, assemble, sign, submit
	// snippet:end quickstart
	return nil
}
