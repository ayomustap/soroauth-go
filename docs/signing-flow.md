# Signing Flow

This is the path from an unsigned authorization entry to a submitted
transaction. The [signing-flow diagram](diagrams/signing-flow.svg) shows the
same sequence visually; [ARCHITECTURE.md](../ARCHITECTURE.md) explains the
credential arms and protocol rules, and [e2e/README.md](../e2e/README.md) covers
the live two-pass flow.

1. **Record the invocation.** Build the transaction with `txnbuild`, then run
   record-mode simulation. `rpcflow.SimulateRecord` exposes this pass by itself;
   `rpcflow.SignAndSubmit` also runs it and obtains the unsigned entries the
   host recorded.
2. **Confirm the credential arm.** Inspect the returned entry with `Inspect`.
   The arm determines the signing preimage. `UseUpgradedAuth` is a best-effort
   request during recording; use `UpgradeToV2` when an unsigned legacy entry
   must be converted explicitly.
3. **Build the bytes to approve.** `Preimage` selects the protocol-defined
   `HashIdPreimage` from the credential arm, network, nonce, invocation and
   chosen expiration. `Payload` marshals that preimage and computes its SHA-256
   hash.
4. **Sign and write the credential.** `AuthorizeEntry` builds the preimage,
   calls `Signer.Sign` with both the preimage and payload, and writes the
   returned `ScVal` only to the matching credential node. `AuthorizeAll` applies
   the matching signers to a batch; `rpcflow.SignAndSubmit` uses it for the
   entries from record mode.
5. **Enforce, assemble and submit.** `rpcflow.Submit` simulates again in enforce
   mode with the signed entries, applies the returned resources, builds and
   signs the transaction envelope with `txnbuild`, then sends it and polls for a
   terminal result. `rpcflow.SignAndSubmit` orchestrates the complete flow.

The enforce pass is required because the signatures change the transaction's
resource requirements. For an externally signed entry, pass it to
`rpcflow.Submit`; do not submit the earlier record-mode envelope.
