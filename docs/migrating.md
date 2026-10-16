# Migrating hand-rolled auth entry signing to soroauth

A guide for teams replacing their own Soroban authorization signing code with
soroauth. You already have working code; what you need to know is where soroauth
differs from what you wrote — and where it differs from the JS SDK you may be
porting from.

Read alongside the [README](../README.md) (Quickstart, credential types, the
two-pass simulation requirement) and [ARCHITECTURE.md](../ARCHITECTURE.md) (the
signing flow). The passkey-specific path has its own guide:
[passkeys.md](passkeys.md).

## The mental model shift

Hand-rolled signing code usually signs _bytes it assembled itself_. soroauth's
model is narrower and is what makes it verifiable:

1. The **entry** comes from `simulateTransaction` — you do not build
   `SorobanAuthorizationEntry` trees by hand except when wrapping delegates
   (`WithDelegates`) or signing an invocation from scratch
   (`AuthorizeInvocation`).
2. The **preimage** is built by `Preimage` from the entry, a `validUntilLedger`,
   and the network passphrase. Which XDR variant applies is decided by the
   entry's credentials arm, not by a flag you pass.
3. The **payload** is `Payload(preimage)` — `SHA-256` of the preimage's XDR.
4. A **Signer** produces the signature `ScVal` and `AuthorizeEntry` writes it
   onto exactly the nodes whose address matches the target.

If your code does these four steps in a different order or with different
inputs, the mapping table below is where to look first.

## Mapping your existing patterns

| Hand-rolled pattern                                                                       | soroauth call                                                | Notes                                                                                                                                                                                                                  |
| ----------------------------------------------------------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Assembling the `HashIdPreimage` union by hand                                             | `Preimage(entry, validUntilLedger, passphrase)`              | The variant is chosen by the credentials arm: legacy → envelope type 9, V2 and delegates → type 10 bound to the top-level address. Source-account entries return `ErrSourceAccountCredentials`, not an empty preimage. |
| `sha256.Sum256(preimage.MarshalBinary())`                                                 | `Payload(preimage)`                                          | Same bytes; the wrapper exists so the payload's provenance is traceable.                                                                                                                                               |
| `kp.Sign(payload[:])` then building the `{public_key, signature}` map                     | `NewEd25519Signer(kp)`                                       | The signer verifies its own signature before returning (`ErrSignatureMismatch`) — the self-check hand-rolled code usually lacks.                                                                                       |
| A loop building one signature map per key, sorted or not                                  | `NewAccountMultiSigner(account, kps...)`                     | Sorts strictly ascending by raw public key and caps at 20 — the host refuses anything else ("public keys are not ordered", MAX_ACCOUNT_SIGNATURES = 20 in `rs-soroban-env`'s `account_contract.rs`).                   |
| Writing the signature into the entry and bumping `signature_expiration_ledger` separately | `AuthorizeEntry`                                             | Signs over **and** stores the same `validUntilLedger`. Divergence between the two is the classic silent failure: the entry looks complete and fails on-chain after fees.                                               |
| Building a fresh entry, nonce included                                                    | `AuthorizeInvocation`                                        | Nonce from `crypto/rand`, big-endian int64; default arm is V2 (matching `@stellar/stellar-sdk@17.1.0`, whose `authorizeInvocation` defaults `authV2 = true`), `Legacy: true` for the legacy arm.                       |
| A `for` loop over entries calling your sign function                                      | `AuthorizeAll`                                               | All-or-nothing: any error returns a nil slice, and an address-arm entry with no matching signer is `ErrMissingSigner`, never a silent skip.                                                                            |
| Decoding a `TransactionEnvelope`, finding the `InvokeHostFunction`, digging out `Auth`    | `AuthorizeEnvelope` / `InspectEnvelope` / `EnvelopePayloads` | Fee-bump envelopes are read through to the inner transaction; an envelope with no invoke operation is `ErrNoInvokeOperation`, not an empty result.                                                                     |
| A custom account contract's signature shape, hand-assembled                               | `SignerFunc` (or `NewPasskeySigner` for WebAuthn)            | The `ScVal` you return is written verbatim; see [passkeys.md](passkeys.md) for the shape-and-verify pattern.                                                                                                           |
| A one-off script computing "the last ledger this is valid until"                          | `ExpirationAfter(latestLedger, ledgers)`                     | Refuses `ledgers == 0` and overflow; the value is inclusive (the host rejects only when `current > live_until`), with a network-side ceiling this library deliberately does not hard-code.                             |

## The four documented differences from the JS SDK

If your old code was ported from `@stellar/stellar-sdk`'s `authorizeEntry`,
these four deviations will bite during migration. They are deliberate and
documented in the README's "Differences from the JS SDK" section; they are
repeated here because each one changes what your migrated code must pass.

1. **A signature is only written to a node whose address matches the target.**
   The JS reference writes to the top-level node when no target is given, even
   if the key belongs to someone else. soroauth returns
   `ErrNoMatchingCredentialNode` instead. Migration consequence: a call that
   "just worked" in JS without a target now needs `ForAddress(...)` or a signer
   whose `Address()` is the node's address.
2. **No default write to the top-level node**, for the same reason — a signature
   on the wrong node is a transaction that pays fees and then fails.
3. **The signer is never invoked when nothing matches.** The zero-match and
   already-signed checks run _before_ signing, so a hardware wallet or remote
   signer is never asked to approve an entry that is about to be discarded.
   Migration consequence: a call that used to "succeed" while signing nothing
   now returns an error — treat the error as the correct outcome.
4. **`AccountMultiSigner` has no JS equivalent.** If your hand-rolled code
   assembled classic-account multisig vectors, this replaces it with the
   host-required ordering and cap enforced for you.

One additional strictness, adjacent to the four: **wrapping or upgrading an
entry that already carries a signature returns `ErrAlreadySigned`**
(`WithDelegates`, `UpgradeToV2`), where JS silently discards the old signature.
The payload changes under both operations, so the old signature would no longer
verify — JS loses that silently; soroauth refuses.

The target-address rule also has an escape hatch for the one legitimate
re-signing flow: `AllowResign()` lifts the already-signed guard, optionally
scoped to named addresses. The expiration guard is never lifted — re-signing one
delegate node at a different `validUntilLedger` would invalidate the others'
signatures, because every node in a delegates tree commits to the same payload.

## Verification: same bytes before and after

A migration should prove the new path produces what the old path produced. The
cheapest strong check: capture one real output of your old code as a baseline,
run the same inputs through soroauth, and compare the XDR bytes.

```go
// The old code's output, captured once and frozen as the baseline. It is a
// blob from outside this program, so it is decoded at the library's bound.
baseline, err := soroauth.DecodeAuthorizationEntry(baselineB64)
if err != nil {
    return false, err
}

// The same inputs, signed with soroauth instead.
migrated, err := soroauth.AuthorizeEntry(ctx, entry, soroauth.NewEd25519Signer(kp),
    validUntilLedger, networkPassphrase)
if err != nil {
    return false, err
}

// Byte-for-byte. Anything else means the migration changed what a host
// would see, and the difference must be explained before this becomes
// the new signing path — see the caveats in docs/migrating.md.
got, err := migrated.MarshalBinary()
if err != nil {
    return false, err
}
want, err := baseline.MarshalBinary()
if err != nil {
    return false, err
}
if !bytes.Equal(got, want) {
    return false, nil
}
```

This snippet is extracted from compiled source in
`internal/readmesnippets/migrate.go`
(`TestMigratingGuideSnippetsMatchTheirSource` fails if this guide drifts from
it).

Ed25519 signatures are deterministic, so for a classic account with a single key
this comparison is exact: same key, same nonce, same `validUntilLedger`, same
network passphrase, same invocation ⇒ same 64-byte signature ⇒ same entry bytes.
Capture the baseline with the _same_ nonce the entry already carries (do not
regenerate one), and the same `validUntilLedger` your old code stored.

Two further checks worth running once per credential arm:

- The golden vectors (`testdata/vectors/*.json`) are this same comparison,
  already committed: soroauth's preimage, payload and signed entry are
  byte-identical to `@stellar/stellar-sdk@17.1.0`'s for every arm, including
  delegate trees. If your old code was the JS SDK, the vectors _are_ your
  migration test.
- `soroauth inspect --entry <base64>` renders the arm, address, nonce,
  expiration and signed-node flags of both the baseline and the migrated entry,
  which is the fastest way to see _what_ differs when the byte comparison fails:

```go
baseline, err := soroauth.DecodeAuthorizationEntry(baselineB64)
if err != nil {
    return err
}
oldInfo, err := soroauth.Inspect(baseline)
if err != nil {
    return err
}
_ = oldInfo // arm, address, nonce, expiration, signed-node flags
```

### When the bytes should differ

Some migrations legitimately change the bytes, and the comparison above will
fail correctly. Know these before you start:

- **Migrating to V2.** `UpgradeToV2` changes the arm, so the payload and entry
  differ from the legacy baseline — by design; that is what address-binding
  buys. Verify the _new_ entry the way the golden vectors do: rebuild the
  preimage from the migrated entry and check the payload.
- **A different `validUntilLedger` or passphrase** changes everything. The
  passphrase is inside the preimage; testnet and public bytes are never
  comparable.
- **Multisig ordering.** If your old code sorted by address string rather than
  raw public key, the migrated vector is ordered differently — and the host
  requires soroauth's ordering.
- **Delegate trees.** `WithDelegates` sorts every level by the XDR encoding of
  the address. If your old code appended delegates in a different order, the
  trees differ; soroauth's is the order CAP-71-01 requires.

In each case the difference is explained, not accommodated: fix the expectation
(or the old code's habit), never the comparison.

## A migration checklist

- [ ] Inventory every code path that touches a `SorobanAuthorizationEntry`,
      noting which arm each one handles.
- [ ] Map each path through the table above; note the ones that need
      `ForAddress` they did not need before (difference 1).
- [ ] Capture one baseline entry per arm from the old code, frozen as base64.
- [ ] Run the byte-identical comparison per arm; investigate every difference
      using the "should differ" list, and explain each one in writing.
- [ ] Re-run the enforcing simulation pass after signing — signing changes the
      resource fee; see the README's "The two-pass simulation requirement".
- [ ] Delete the old signing code in the same change that lands soroauth, so the
      two paths cannot drift back apart.
