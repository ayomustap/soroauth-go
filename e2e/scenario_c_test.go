//go:build e2e

package e2e

import (
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"

	"github.com/soroauth/soroauth-go"
)

// makeMultisig turns an account into a 2-of-2: the master key keeps weight 1,
// a second signer is added at weight 1, and the medium threshold is raised to
// 2 so a transfer needs both.
func (h *harness) makeMultisig(t *testing.T, account *keypair.Full, extra *keypair.Full) {
	t.Helper()

	tx, err := txnbuild.NewTransaction(txnbuild.TransactionParams{
		SourceAccount:        h.account(t, account.Address()),
		IncrementSequenceNum: true,
		BaseFee:              txnbuild.MinBaseFee * 100,
		Preconditions:        txnbuild.Preconditions{TimeBounds: txnbuild.NewInfiniteTimeout()},
		Operations: []txnbuild.Operation{
			&txnbuild.SetOptions{
				MasterWeight:    txnbuild.NewThreshold(1),
				LowThreshold:    txnbuild.NewThreshold(1),
				MediumThreshold: txnbuild.NewThreshold(2),
				HighThreshold:   txnbuild.NewThreshold(2),
				Signer:          &txnbuild.Signer{Address: extra.Address(), Weight: 1},
			},
		},
	})
	if err != nil {
		t.Fatalf("building the setOptions transaction: %v", err)
	}

	// The threshold change takes effect after this transaction, so it is
	// still signed by the master key alone.
	tx, err = tx.Sign(h.passphrase, account)
	if err != nil {
		t.Fatalf("signing the setOptions transaction: %v", err)
	}

	result := h.send(t, tx)
	if result.Status != rpc.TransactionStatusSuccess {
		t.Fatalf("configuring multisig failed (status %s):\n%s", result.Status, result.RawError)
	}
	t.Logf("multisig configured in ledger %d (tx %s)", result.Ledger, result.Hash)
}

// TestScenarioC proves AccountMultiSigner is correct in both directions on one
// account: two signatures meet a 2-of-2 medium threshold, and one signature is
// refused for insufficient weight.
//
// The two halves share the same accounts and the same configured thresholds,
// so the contrast cannot drift: if the setup changed such that the threshold
// was never raised, the rejection half would start passing the full-signature
// transfer and fail the test. This signer has no JS equivalent, so the golden
// vectors cannot cover it; this is its evidence.
func TestScenarioC(t *testing.T) {
	h := newHarness(t)

	payer := h.newAccount(t, "payer P")
	multisig := h.newAccount(t, "account M")
	second := h.newAccount(t, "signer M2")
	to := h.newAccount(t, "recipient B")

	// One setup, used by both subtests below.
	h.makeMultisig(t, multisig, second)

	op := h.transferOp(t, scAddressOf(t, multisig.Address()), scAddressOf(t, to.Address()),
		transferAmount, payer.Address())

	t.Run("threshold-met", func(t *testing.T) {
		signer, err := soroauth.NewAccountMultiSigner(multisig.Address(), multisig, second)
		if err != nil {
			t.Fatalf("building the multi signer: %v", err)
		}

		result := runScenario(t, h, scenarioSpec{
			payer:        payer,
			op:           op,
			signers:      []soroauth.Signer{signer},
			upgradedAuth: true,
		})

		t.Logf("tx hash: %s", result.Hash)
		t.Logf("ledger:  %d", result.Ledger)
		t.Logf("arm:     %s", result.Arm)
		t.Logf("link:    %s%s", runExplorerBase, result.Hash)

		record(scenarioResult{
			ID:     "C",
			Name:   "AccountMultiSigner accepted live",
			Proves: "A signature vector from soroauth.NewAccountMultiSigner meets a 2-of-2 medium threshold on a classic account.",
			TxHash: result.Hash,
			Ledger: result.Ledger,
			Arm:    result.Arm,
			Notes: []string{
				"Account M has its master key at weight 1 plus a second signer at weight 1, with the medium threshold raised to 2, so one signature alone is not enough.",
				"Keys are sorted strictly ascending by raw public key, which is what the host requires.",
			},
			Succeeded: result.Status == rpc.TransactionStatusSuccess,
			RawError:  result.RawError,
		})

		if result.Status != rpc.TransactionStatusSuccess {
			t.Fatalf("scenario C failed on-chain (status %s):\n%s", result.Status, result.RawError)
		}
	})

	t.Run("threshold-not-met", func(t *testing.T) {
		// Deliberately only the master key, which carries weight 1 of the 2
		// required. Same account, same thresholds, same transfer: only the
		// signatures supplied differ, which is what makes this the control.
		signer, err := soroauth.NewAccountMultiSigner(multisig.Address(), multisig)
		if err != nil {
			t.Fatalf("building the single-key multi signer: %v", err)
		}

		result := runScenario(t, h, scenarioSpec{
			payer:         payer,
			op:            op,
			signers:       []soroauth.Signer{signer},
			upgradedAuth:  true,
			expectFailure: true,
		})

		t.Logf("tx hash:   %s", result.Hash)
		t.Logf("status:    %s", result.Status)
		t.Logf("arm:       %s", result.Arm)
		t.Logf("RAW ERROR:\n%s", result.RawError)

		if result.Status == rpc.TransactionStatusSuccess {
			t.Fatal("a single signature met a threshold of 2; the account was not actually multisig")
		}
		if result.RawError == "" {
			t.Error("no raw error was captured, so there is nothing to report")
		}

		// It is not enough that the transaction failed. It has to have failed
		// because the signature weight did not meet the threshold — the host's
		// own check in check_account_authentication — rather than because it
		// ran out of instructions before that check was reached.
		//
		// The host raises ContractError::AuthenticationError, which is 5
		// (rs-soroban-env builtin_contracts/contract_error.rs:18), with the
		// message "signature weight is lower than threshold" and the weight and
		// threshold as arguments
		// (builtin_contracts/account_contract.rs, check_account_authentication).
		const (
			wantMessage       = "signature weight is lower than threshold"
			wantWeight        = 1
			wantThreshold     = 2
			authenticationErr = 5
		)

		details := hostErrorDetails(t, result.Diagnostics)
		var matched bool
		for _, detail := range details {
			if detail.Message != wantMessage {
				continue
			}
			matched = true
			if !detail.HasCode || detail.ContractCode != authenticationErr {
				t.Errorf("the weight error carried contract code %v (present=%v), want %d (ContractError::AuthenticationError)",
					detail.ContractCode, detail.HasCode, authenticationErr)
			}
			if len(detail.Args) != 2 {
				t.Errorf("the weight error carried args %v, want [weight threshold]", detail.Args)
				continue
			}
			if detail.Args[0] != wantWeight || detail.Args[1] != wantThreshold {
				t.Errorf("the weight error reports weight %d against threshold %d, want %d and %d",
					detail.Args[0], detail.Args[1], wantWeight, wantThreshold)
			}
		}
		if !matched {
			t.Errorf("no diagnostic carried %q; the transaction failed, but not for the reason this control is about.\nHost errors seen: %+v",
				wantMessage, details)
		} else {
			t.Logf("confirmed: ContractError::AuthenticationError (%d), %q, weight %d against threshold %d",
				authenticationErr, wantMessage, wantWeight, wantThreshold)
		}

		record(scenarioResult{
			ID:              "C-control",
			Name:            "a single signature does not meet a 2-of-2 threshold",
			Proves:          "Scenario C is not passing by accident: the same account and the same transfer, signed with only one of the two required keys, is refused by the host for insufficient signature weight.",
			TxHash:          result.Hash,
			Ledger:          result.Ledger,
			Arm:             result.Arm,
			Succeeded:       result.Status != rpc.TransactionStatusSuccess,
			ExpectRejection: true,
			RawError:        result.RawError,
			Notes: []string{
				"Account M: master key weight 1, second signer weight 1, medium threshold 2.",
				"Signed with the master key alone, so the weight is 1 against a threshold of 2.",
				"Expected host error: ContractError::AuthenticationError (5), \"signature weight is lower than threshold\", args weight=1 threshold=2.",
			},
		})
	})
}
