//go:build e2e

package e2e

import (
	"context"
	"testing"

	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// TestScenarioThreeLevelDelegates submits a real three-level delegate tree to
// testnet and decodes the submitted envelope back to observe the shape.
//
// The depth is built by chaining modular-account fixtures:
//
//	account A (modular) delegates to B (modular)
//	account B (modular) delegates to C (modular)
//	account C (modular) delegates to D (G account)
//
// Each contract account authenticates through its own stored signer set using
// env.custom_account().get_delegated_signers() and delegate_auth, which is the
// CAP-71-01 delegation path. D is the only node that can produce a classic
// Ed25519 signature, so it is the node soroauth signs; the contract nodes carry
// Void, which is what a contract account with no signature of its own expects.
//
// The scenario asserts:
//
//   - the observed tree in the submitted envelope is three delegate levels
//     deep, not merely that the transaction succeeded;
//   - the leaf signature verifies over the payload the entry itself commits to,
//     which is the CAP's central claim: every node authorizes the same bytes.
func TestScenarioThreeLevelDelegates(t *testing.T) {
	h := newHarness(t)

	deployer := h.newAccount(t, "deployer")
	payer := h.newAccount(t, "payer P")
	to := h.newAccount(t, "recipient B")
	leaf := h.newAccount(t, "delegate D")

	// Deploy bottom-up, because each constructor names the next contract.
	c := h.deployModularAccount(t, deployer, []string{leaf.Address()})
	b := h.deployModularAccount(t, deployer, []string{c.ContractAddress})
	a := h.deployModularAccount(t, deployer, []string{b.ContractAddress})
	h.fundContract(t, deployer, a.ContractAddress, transferAmount*5)

	t.Logf("account A (top-level): %s", a.ContractAddress)
	t.Logf("account B (level 1):   %s", b.ContractAddress)
	t.Logf("account C (level 2):   %s", c.ContractAddress)
	t.Logf("delegate D (level 3):  %s", leaf.Address())

	op := h.transferOp(t, scAddressOf(t, a.ContractAddress), scAddressOf(t, to.Address()),
		transferAmount, payer.Address())

	// --- Record: the host reports that A must authorize the transfer. ---
	recordTx := h.build(t, h.account(t, payer.Address()), op)
	recorded := h.simulate(t, recordTx, rpc.AuthModeRecord, true)
	entries := recordedAuthEntries(t, recorded)

	validUntil, err := soroauth.ExpirationAfter(h.latestLedger(t), 1000)
	if err != nil {
		t.Fatalf("computing the expiration ledger: %v", err)
	}

	// --- Wrap: A's entry becomes a delegates entry with a three-level tree. ---
	delegates := []soroauth.Delegate{{
		Address: b.ContractAddress,
		Nested: []soroauth.Delegate{{
			Address: c.ContractAddress,
			Nested: []soroauth.Delegate{{
				Address: leaf.Address(),
			}},
		}},
	}}

	prepared := make([]xdr.SorobanAuthorizationEntry, 0, len(entries))
	for i, entry := range entries {
		info, err := soroauth.Inspect(entry)
		if err != nil {
			t.Fatalf("inspecting recorded entry %d: %v", i, err)
		}
		if info.CredentialType == soroauth.CredentialTypeSourceAccount || info.Address != a.ContractAddress {
			prepared = append(prepared, entry)
			continue
		}
		wrapped, err := soroauth.WithDelegates(entry, validUntil, delegates, nil)
		if err != nil {
			t.Fatalf("WithDelegates on entry %d: %v", i, err)
		}
		prepared = append(prepared, wrapped)
	}

	// --- Sign: only the G-account leaf can sign. ---
	signed := make([]xdr.SorobanAuthorizationEntry, 0, len(prepared))
	for i, entry := range prepared {
		info, err := soroauth.Inspect(entry)
		if err != nil {
			t.Fatalf("inspecting prepared entry %d: %v", i, err)
		}
		if info.CredentialType == soroauth.CredentialTypeSourceAccount {
			signed = append(signed, entry)
			continue
		}
		out, err := soroauth.AuthorizeEntry(context.Background(), entry,
			soroauth.NewEd25519Signer(leaf), validUntil, h.passphrase,
			soroauth.ForAddress(leaf.Address()))
		if err != nil {
			t.Fatalf("signing the leaf delegate in entry %d: %v", i, err)
		}
		signed = append(signed, out)
	}

	var delegatesEntry xdr.SorobanAuthorizationEntry
	for _, entry := range signed {
		info, err := soroauth.Inspect(entry)
		if err != nil {
			t.Fatalf("inspecting signed entry: %v", err)
		}
		if info.CredentialType == soroauth.CredentialTypeAddressWithDelegates {
			delegatesEntry = entry
			break
		}
	}
	if delegatesEntry.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates {
		t.Fatal("no delegates-arm entry was produced")
	}

	// --- Verify offline: the leaf's signature covers the entry's payload. ---
	//
	// VerifyEntry rebuilds the preimage from the entry as it stands — including
	// the shared expiration — and checks every node it can. Contract nodes are
	// reported cannot_check because only their own __check_auth defines their
	// signature shape; the G-account leaf must report verified.
	report, err := soroauth.VerifyEntry(delegatesEntry, h.passphrase)
	if err != nil {
		t.Fatalf("verifying the three-level entry offline: %v", err)
	}
	var leafVerified bool
	for _, node := range report.Nodes {
		t.Logf("verified node %s: %s %s", node.Address, node.Verdict, node.Reason)
		if node.Address == leaf.Address() {
			if node.Verdict != soroauth.VerdictVerified {
				t.Fatalf("the leaf signature did not verify over the entry payload: %s (%s)",
					node.Verdict, node.Reason)
			}
			leafVerified = true
		}
	}
	if !leafVerified {
		t.Fatal("the leaf delegate does not appear in the verification report")
	}

	// --- Enforce, assemble, sign, submit. ---
	op.Auth = signed

	enforceTx := h.build(t, h.account(t, payer.Address()), op)
	enforceSim := h.simulate(t, enforceTx, rpc.AuthModeEnforce, false)

	finalTx := h.assembleWithHeadroom(t, h.account(t, payer.Address()), op, enforceSim, 1)
	finalTx, err = finalTx.Sign(h.passphrase, payer)
	if err != nil {
		t.Fatalf("signing the envelope: %v", err)
	}

	// Decode the envelope that is actually going out. §5.10 requires the tree
	// shape be observed rather than assumed from what was built.
	encoded, err := finalTx.Base64()
	if err != nil {
		t.Fatalf("encoding the final transaction: %v", err)
	}
	maxDepth, delegateCount := observeDelegateTree(t, encoded)

	if maxDepth != 3 {
		t.Errorf("the submitted envelope carries a delegate tree %d levels deep, want 3", maxDepth)
	}
	if delegateCount != 3 {
		t.Errorf("the submitted envelope carries %d delegate nodes, want 3 (B, C, D)", delegateCount)
	}

	result := h.send(t, finalTx)

	t.Logf("tx hash: %s", result.Hash)
	t.Logf("ledger:  %d", result.Ledger)
	t.Logf("arm:     %s", result.Arm)
	t.Logf("link:    %s%s", runExplorerBase, result.Hash)

	record(scenarioResult{
		ID:        "Q",
		Name:      "a three-level nested delegate tree is accepted live",
		Proves:    "The host walks a delegate tree three levels deep (A -> B -> C -> D) and accepts it when every contract level forwards its authorization and the G-account leaf signs the shared payload.",
		TxHash:    result.Hash,
		Ledger:    result.Ledger,
		Arm:       result.Arm,
		Succeeded: result.Status == rpc.TransactionStatusSuccess,
		RawError:  result.RawError,
		Notes: []string{
			"Account A (top-level): " + a.ContractAddress,
			"Account B (level 1):   " + b.ContractAddress,
			"Account C (level 2):   " + c.ContractAddress,
			"Delegate D (level 3):  " + leaf.Address(),
			"The submitted envelope was decoded back and its tree shape observed, not inferred from what was built.",
			"Expected shape: 3 delegate levels and 3 delegate nodes.",
			"The G-account leaf signature verifies over the payload built from the entry itself; contract nodes carry Void and authenticate through their own nested delegates, which CAP-71-01 permits.",
			"Contract deploy tx A: " + a.CreateTxHash + ", B: " + b.CreateTxHash + ", C: " + c.CreateTxHash,
		},
	})

	if result.Status != rpc.TransactionStatusSuccess {
		t.Fatalf("the three-level delegate submission failed (status %s):\n%s", result.Status, result.RawError)
	}
	if result.Arm != "SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates" {
		t.Errorf("the submitted envelope carried arm %q, want the delegates arm", result.Arm)
	}
}

// observeDelegateTree decodes a submitted envelope and reports the delegate
// tree's depth (root's direct delegates are depth 1) and node count. It logs
// every observed node so a failing run shows what the envelope actually
// carried.
func observeDelegateTree(t *testing.T, envelopeBase64 string) (maxDepth, nodeCount int) {
	t.Helper()

	var envelope xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(envelopeBase64, &envelope); err != nil {
		t.Fatalf("decoding the submitted envelope: %v", err)
	}

	operations := envelope.Operations()
	if len(operations) != 1 {
		t.Fatalf("the submitted envelope carries %d operations, want 1", len(operations))
	}
	invoke, ok := operations[0].Body.GetInvokeHostFunctionOp()
	if !ok {
		t.Fatal("the submitted operation is not an invokeHostFunction")
	}
	if len(invoke.Auth) != 1 {
		t.Fatalf("the submitted operation carries %d auth entries, want 1", len(invoke.Auth))
	}

	info, err := soroauth.Inspect(invoke.Auth[0])
	if err != nil {
		t.Fatalf("inspecting the submitted auth entry: %v", err)
	}
	if info.CredentialType != soroauth.CredentialTypeAddressWithDelegates {
		t.Fatalf("the submitted auth entry is on the %q arm, want address_with_delegates", info.CredentialType)
	}

	t.Logf("observed top-level node: %s (signed=%v)", info.Address, info.TopLevelSigned)

	var walk func(nodes []soroauth.NodeInfo, depth int)
	walk = func(nodes []soroauth.NodeInfo, depth int) {
		for _, node := range nodes {
			nodeCount++
			if depth > maxDepth {
				maxDepth = depth
			}
			t.Logf("observed delegate node: depth %d, address %s, signed=%v", depth, node.Address, node.Signed)
			walk(node.Nested, depth+1)
		}
	}
	walk(info.Delegates, 1)

	return maxDepth, nodeCount
}
