//go:build e2e

package e2e

import (
	"context"
	"strconv"
	"testing"

	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"

	"github.com/soroauth/soroauth-go"
)

// TestScenarioNonceReplayRejected proves that a signed entry cannot be
// replayed. It signs one recording pass's entry, submits it successfully, then
// submits a second envelope carrying the *same* signed entry — same address,
// same nonce — and requires the host to refuse it with its nonce error. A
// third submission with a fresh recording pass (and therefore a fresh nonce)
// then succeeds, which is the control showing the account is not simply broken.
//
// The scenario uses its own payer, signer and recipient, all generated at
// runtime, so no other scenario can consume its nonce or poison its account.
func TestScenarioNonceReplayRejected(t *testing.T) {
	h := newHarness(t)

	payer := h.newAccount(t, "payer P")
	signer := h.newAccount(t, "signer S")
	to := h.newAccount(t, "recipient B")

	op := h.transferOp(t, scAddressOf(t, signer.Address()), scAddressOf(t, to.Address()),
		transferAmount, payer.Address())

	// One recording pass. The host assigns the nonce in record mode
	// (rs-soroban-env auth.rs: it draws a random nonce and consumes it in the
	// recording tracker), so signing this entry twice reuses that one nonce.
	recordTx := h.build(t, h.account(t, payer.Address()), op)
	recorded := h.simulate(t, recordTx, rpc.AuthModeRecord, false)
	entries := recordedAuthEntries(t, recorded)

	validUntil, err := soroauth.ExpirationAfter(h.latestLedger(t), 1000)
	if err != nil {
		t.Fatalf("computing the expiration ledger: %v", err)
	}

	signed, err := soroauth.AuthorizeAll(context.Background(), entries,
		[]soroauth.Signer{soroauth.NewEd25519Signer(signer)}, validUntil, h.passphrase)
	if err != nil {
		t.Fatalf("AuthorizeAll: %v", err)
	}

	info, err := soroauth.Inspect(signed[0])
	if err != nil {
		t.Fatalf("inspecting the signed entry: %v", err)
	}
	t.Logf("entry nonce: %d", info.Nonce)

	// --- First submission: the nonce has not been consumed yet. ---
	op.Auth = signed

	enforceTx := h.build(t, h.account(t, payer.Address()), op)
	enforceSim := h.simulate(t, enforceTx, rpc.AuthModeEnforce, false)

	firstTx := h.assembleWithHeadroom(t, h.account(t, payer.Address()), op, enforceSim, 1)
	firstTx, err = firstTx.Sign(h.passphrase, payer)
	if err != nil {
		t.Fatalf("signing the first envelope: %v", err)
	}

	first := h.send(t, firstTx)
	if first.Status != rpc.TransactionStatusSuccess {
		t.Fatalf("the first submission should succeed, got status %s:\n%s", first.Status, first.RawError)
	}
	t.Logf("first tx hash: %s", first.Hash)
	t.Logf("first ledger:  %d", first.Ledger)
	t.Logf("arm:           %s", first.Arm)

	record(scenarioResult{
		ID:        "N",
		Name:      "nonce replay: the first submission succeeds",
		Proves:    "A sorauth-signed entry is accepted by the host, consuming its nonce.",
		TxHash:    first.Hash,
		Ledger:    first.Ledger,
		Arm:       first.Arm,
		Succeeded: first.Status == rpc.TransactionStatusSuccess,
		RawError:  first.RawError,
		Notes: []string{
			"Uses a freshly generated and funded account, so the nonce state is known.",
			"The signed entry's nonce is " + strconv.FormatInt(info.Nonce, 10) + ".",
		},
	})

	// --- Second submission: the same signed entry, replayed. ---
	//
	// The enforcing simulation is skipped deliberately. It reads the ledger
	// state the first submission already changed, so it fails locally with the
	// very nonce error under test; the point is to have the real host refuse
	// it in an applied transaction. Resources therefore come from the original
	// recording pass with the rejection headroom.
	op.Auth = signed

	replayTx := h.assembleWithHeadroom(t, h.account(t, payer.Address()), op, recorded, rejectionHeadroom)
	replayTx, err = replayTx.Sign(h.passphrase, payer)
	if err != nil {
		t.Fatalf("signing the replay envelope: %v", err)
	}

	replay := h.send(t, replayTx)
	if replay.Status == rpc.TransactionStatusSuccess {
		t.Fatal("the host accepted a replayed nonce; the entry's replay protection is not working")
	}
	if replay.RawError == "" {
		t.Fatal("no raw error was captured for the replay, so there is nothing to assert or report")
	}

	assertHostError(t, replay.Diagnostics, scErrorTypeAuth, scErrorCodeExistingValue, nonceReusedMessage)

	t.Logf("replay tx hash: %s", replay.Hash)
	t.Logf("replay status:  %s", replay.Status)
	t.Logf("replay arm:     %s", replay.Arm)
	t.Logf("RAW ERROR:\n%s", replay.RawError)

	record(scenarioResult{
		ID:              "O",
		Name:            "nonce replay: the second submission is rejected",
		Proves:          "A second transaction carrying the same signed entry, and therefore the same nonce, is refused by the host with Auth / ExistingValue, \"nonce already exists for address\".",
		TxHash:          replay.Hash,
		Ledger:          replay.Ledger,
		Arm:             replay.Arm,
		Succeeded:       replay.Status != rpc.TransactionStatusSuccess,
		ExpectRejection: true,
		RawError:        replay.RawError,
		Notes: []string{
			"The second envelope carries the exact signed entry the first one carried, so the address and nonce are identical.",
			"The enforcing simulation pass is skipped for this rejection: it would fail locally with the error under test.",
			"Expected host error: ScErrorType::Auth (9), ScErrorCode::ExistingValue (4), \"nonce already exists for address\" (rs-soroban-env soroban-env-host/src/auth.rs, consume_nonce).",
		},
	})

	// --- Control: a fresh nonce succeeds afterwards. ---
	//
	// Without this, the replay rejection could be explained by the account
	// being unusable for any reason at all.
	//
	// Clear the auth entries first: a recording pass must start from the
	// operation as it was before anything was signed, or the host executes the
	// old entry instead of recording a fresh requirement.
	op.Auth = nil
	controlRecordTx := h.build(t, h.account(t, payer.Address()), op)
	controlRecorded := h.simulate(t, controlRecordTx, rpc.AuthModeRecord, false)
	controlEntries := recordedAuthEntries(t, controlRecorded)

	controlValidUntil, err := soroauth.ExpirationAfter(h.latestLedger(t), 1000)
	if err != nil {
		t.Fatalf("computing the control expiration: %v", err)
	}

	controlSigned, err := soroauth.AuthorizeAll(context.Background(), controlEntries,
		[]soroauth.Signer{soroauth.NewEd25519Signer(signer)}, controlValidUntil, h.passphrase)
	if err != nil {
		t.Fatalf("AuthorizeAll for the control: %v", err)
	}

	controlInfo, err := soroauth.Inspect(controlSigned[0])
	if err != nil {
		t.Fatalf("inspecting the control entry: %v", err)
	}
	if controlInfo.Nonce == info.Nonce {
		t.Fatalf("the control entry reused nonce %d; the recording pass did not produce a fresh one, so this proves nothing",
			controlInfo.Nonce)
	}
	t.Logf("control entry nonce: %d (fresh)", controlInfo.Nonce)

	op.Auth = controlSigned

	controlEnforceTx := h.build(t, h.account(t, payer.Address()), op)
	controlEnforceSim := h.simulate(t, controlEnforceTx, rpc.AuthModeEnforce, false)

	controlTx := h.assembleWithHeadroom(t, h.account(t, payer.Address()), op, controlEnforceSim, 1)
	controlTx, err = controlTx.Sign(h.passphrase, payer)
	if err != nil {
		t.Fatalf("signing the control envelope: %v", err)
	}

	control := h.send(t, controlTx)
	if control.Status != rpc.TransactionStatusSuccess {
		t.Fatalf("the fresh-nonce control should succeed, got status %s:\n%s", control.Status, control.RawError)
	}
	t.Logf("control tx hash: %s", control.Hash)
	t.Logf("control ledger:  %d", control.Ledger)

	record(scenarioResult{
		ID:        "P",
		Name:      "nonce replay: a control with a fresh nonce succeeds",
		Proves:    "After the replay is refused, a new entry with a fresh nonce is accepted, so the refusal was the nonce check and not a broken account.",
		TxHash:    control.Hash,
		Ledger:    control.Ledger,
		Arm:       control.Arm,
		Succeeded: control.Status == rpc.TransactionStatusSuccess,
		RawError:  control.RawError,
		Notes: []string{
			"Fresh recording pass, so the nonce differs from the replayed one.",
		},
	})
}
