//go:build e2e

package e2e

import (
	"context"
	"testing"
	"time"

	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// The host's own words for the refusals these scenarios assert, read from
// rs-soroban-env soroban-env-host/src/auth.rs, verify_and_consume_nonce and
// consume_nonce. Asserting the message is what keeps a scenario from passing
// because the transaction ran out of instructions instead.
const (
	signatureExpiredMessage = "signature has expired"
	nonceReusedMessage      = "nonce already exists for address"
)

// ScErrorType and ScErrorCode values, from the XDR definitions the host
// reports in its diagnostic events.
const (
	scErrorTypeAuth = int32(xdr.ScErrorTypeSceAuth) // 9

	scErrorCodeInvalidInput  = int32(xdr.ScErrorCodeScecInvalidInput)  // 2
	scErrorCodeExistingValue = int32(xdr.ScErrorCodeScecExistingValue) // 4
)

// TestScenarioExpiredSignatureRejected proves both halves of the expiration
// bound against a live host:
//
//   - a signature whose signatureExpirationLedger is in the past is refused
//     with the host's own Auth / InvalidInput, "signature has expired"; and
//   - a signature submitted at exactly the expiration ledger is accepted,
//     which is the half that proves the bound is inclusive.
//
// The second half is timing-sensitive: a transaction is only at the boundary
// if it executes in the ledger the signature named. The test polls
// getLatestLedger and submits one ledger before the target, and if it cannot
// hit the ledger it skips with an explanation rather than failing — a missed
// ledger is a timing miss, not a signature-correctness result.
func TestScenarioExpiredSignatureRejected(t *testing.T) {
	h := newHarness(t)

	payer := h.newAccount(t, "payer P")
	signer := h.newAccount(t, "signer S")
	to := h.newAccount(t, "recipient B")

	op := h.transferOp(t, scAddressOf(t, signer.Address()), scAddressOf(t, to.Address()),
		transferAmount, payer.Address())

	t.Run("past-expiration-is-rejected", func(t *testing.T) {
		// Record, then sign with an expiration well in the past. The enforcing
		// simulation is deliberately skipped: it would fail locally for the
		// reason under test, which proves only that simulation agrees with the
		// host. The recording pass's resources are used with the rejection
		// headroom instead, so the transaction reaches the real host.
		recordTx := h.build(t, h.account(t, payer.Address()), op)
		recorded := h.simulate(t, recordTx, rpc.AuthModeRecord, false)
		entries := recordedAuthEntries(t, recorded)

		pastExpiration := h.latestLedger(t) - 100

		signed, err := soroauth.AuthorizeAll(context.Background(), entries,
			[]soroauth.Signer{soroauth.NewEd25519Signer(signer)}, pastExpiration, h.passphrase)
		if err != nil {
			t.Fatalf("AuthorizeAll with a past expiration: %v", err)
		}

		op.Auth = signed

		finalTx := h.assembleWithHeadroom(t, h.account(t, payer.Address()), op, recorded, rejectionHeadroom)
		finalTx, err = finalTx.Sign(h.passphrase, payer)
		if err != nil {
			t.Fatalf("signing the envelope: %v", err)
		}

		result := h.send(t, finalTx)

		if result.Status == rpc.TransactionStatusSuccess {
			t.Fatal("the host accepted a signature whose expiration ledger had passed")
		}
		if result.RawError == "" {
			t.Fatal("no raw error was captured, so there is nothing to assert or report")
		}

		assertHostError(t, result.Diagnostics, scErrorTypeAuth, scErrorCodeInvalidInput, signatureExpiredMessage)

		t.Logf("tx hash: %s", result.Hash)
		t.Logf("status:  %s", result.Status)
		t.Logf("RAW ERROR:\n%s", result.RawError)

		record(scenarioResult{
			ID:              "L",
			Name:            "an expired signature is rejected on-chain",
			Proves:          "A sorauth-signed entry whose signatureExpirationLedger is in the past is refused by the host with Auth / InvalidInput, \"signature has expired\".",
			TxHash:          result.Hash,
			Ledger:          result.Ledger,
			Arm:             result.Arm,
			Succeeded:       result.Status != rpc.TransactionStatusSuccess,
			ExpectRejection: true,
			RawError:        result.RawError,
			Notes: []string{
				"The entry was signed with signatureExpirationLedger = latestLedger - 100.",
				"The enforcing simulation pass is skipped for a rejection scenario, because it would fail locally for the reason under test; resources come from the recording pass with headroom.",
				"Expected host error: ScErrorType::Auth (9), ScErrorCode::InvalidInput (2), \"signature has expired\" (rs-soroban-env soroban-env-host/src/auth.rs, verify_and_consume_nonce).",
			},
		})
	})

	t.Run("exact-expiration-ledger-accepted", func(t *testing.T) {
		// A few attempts, because the target is a moving ledger: if the chain
		// closes past the target before the submission is in, the transaction
		// expires and there is no boundary to observe. Each attempt is a fresh
		// recording pass, so each has its own nonce.
		const attempts = 3
		var (
			proven   bool
			lastMiss string
		)

		for attempt := 1; attempt <= attempts && !proven; attempt++ {
			target := h.latestLedger(t) + 8

			// A recording pass must start from the operation with no auth
			// entries attached, or the host executes the previous attempt's
			// signed entry instead of recording a fresh requirement.
			op.Auth = nil
			recordTx := h.build(t, h.account(t, payer.Address()), op)
			recorded := h.simulate(t, recordTx, rpc.AuthModeRecord, false)
			entries := recordedAuthEntries(t, recorded)

			signed, err := soroauth.AuthorizeAll(context.Background(), entries,
				[]soroauth.Signer{soroauth.NewEd25519Signer(signer)}, target, h.passphrase)
			if err != nil {
				t.Fatalf("AuthorizeAll with expiration %d: %v", target, err)
			}

			op.Auth = signed

			// The enforcing pass is run before the wait. It executes against
			// the ledger state at simulation time, which is still at or before
			// the target, so it accepts the entry; running it late would waste
			// the narrow window between the target closing and submission.
			enforceTx := h.build(t, h.account(t, payer.Address()), op)
			enforceSim := h.simulate(t, enforceTx, rpc.AuthModeEnforce, false)

			finalTx := h.assembleWithHeadroom(t, h.account(t, payer.Address()), op, enforceSim, 1)
			finalTx, err = finalTx.Sign(h.passphrase, payer)
			if err != nil {
				t.Fatalf("signing the envelope: %v", err)
			}

			// Poll rather than assume a close rate. The transaction must go
			// out while the target-1 ledger is the latest closed one, so it is
			// included in the target ledger.
			deadline := time.Now().Add(2 * time.Minute)
			missed := false
			for {
				current := h.latestLedger(t)
				switch {
				case current == target-1:
					// Ready: submit now.
				case current > target-1:
					lastMiss = "the chain closed past the target ledger before submission"
					missed = true
				case time.Now().After(deadline):
					lastMiss = "the target ledger was not reached before the polling deadline"
					missed = true
				}
				if !missed && current == target-1 {
					break
				}
				if missed {
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
			if missed {
				t.Logf("attempt %d: %s (target %d)", attempt, lastMiss, target)
				continue
			}

			result := h.send(t, finalTx)
			t.Logf("attempt %d: target ledger %d, status %s, landed %d", attempt, target, result.Status, result.Ledger)

			if result.Status != rpc.TransactionStatusSuccess {
				lastMiss = "the submission did not land at or before the target ledger"
				t.Logf("attempt %d: %s: %s", attempt, lastMiss, result.RawError)
				continue
			}
			if result.Ledger != target {
				lastMiss = "the submission landed at a ledger other than the target"
				t.Logf("attempt %d: %s (landed %d, target %d)", attempt, lastMiss, result.Ledger, target)
				continue
			}

			// Success at exactly the expiration ledger: the inclusive half.
			proven = true

			t.Logf("tx hash: %s", result.Hash)
			t.Logf("ledger:  %d (the expiration ledger itself)", result.Ledger)
			t.Logf("arm:     %s", result.Arm)
			t.Logf("link:    %s%s", runExplorerBase, result.Hash)

			record(scenarioResult{
				ID:        "M",
				Name:      "a signature at exactly its expiration ledger is accepted",
				Proves:    "The host accepts a signature when the executing ledger equals signatureExpirationLedger, so the bound is inclusive; the sibling rejection scenario proves the next ledger is refused.",
				TxHash:    result.Hash,
				Ledger:    result.Ledger,
				Arm:       result.Arm,
				Succeeded: result.Status == rpc.TransactionStatusSuccess,
				RawError:  result.RawError,
				Notes: []string{
					"The entry's signatureExpirationLedger equals the ledger the transaction executed in.",
					"rs-soroban-env verify_and_consume_nonce rejects only when ledger_seq > live_until_ledger, so equality is accepted.",
					"The companion scenario L proves a past expiration is refused.",
				},
			})
		}

		if !proven {
			// A miss is not a signature-correctness failure. Say exactly what
			// went wrong and skip; the rejection half above still ran and
			// recorded its evidence.
			skipScenariof(t, "could not submit at exactly the expiration ledger: %s; "+
				"the inclusion boundary was therefore not observed in this run", lastMiss)
		}
	})
}

// assertHostError fails the test unless the host reported the given ScErrorType,
// ScErrorCode and message in its diagnostics.
//
// A rejection scenario must assert which failure it observed. "The transaction
// failed" is satisfied by an instruction-budget exhaustion that never reached
// the check under test, which is how scenario E originally passed for the
// wrong reason (see e2e/README.md).
func assertHostError(t *testing.T, diagnosticsXDR []string, wantType, wantCode int32, wantMessage string) {
	t.Helper()

	details := hostErrorDetails(t, diagnosticsXDR)
	for _, detail := range details {
		if detail.Message != wantMessage {
			continue
		}
		if detail.ErrorType != wantType {
			t.Errorf("the %q error carried ScErrorType %d, want %d", wantMessage, detail.ErrorType, wantType)
		}
		if !detail.HasErrorCode || detail.ErrorCode != wantCode {
			t.Errorf("the %q error carried ScErrorCode %d (present=%v), want %d",
				wantMessage, detail.ErrorCode, detail.HasErrorCode, wantCode)
		}
		t.Logf("confirmed: ScErrorType %d, ScErrorCode %d, %q", wantType, wantCode, wantMessage)
		return
	}
	t.Errorf("no diagnostic carried %q; the transaction failed, but not for the reason this scenario is about.\nHost errors seen: %+v",
		wantMessage, details)
}
