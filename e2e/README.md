# End-to-end tests

These tests prove soroauth against a live Stellar network. They are the evidence
behind the claim that the signatures this library produces are accepted by a
real host — not by a mock, and not only by the JS reference implementation.

They are excluded from the normal test suite by the `e2e` build tag, because
they create accounts, submit transactions, and wait on ledger close.

## Running them

```sh
make e2e          # against testnet (the default)
make e2e-local    # against a local quickstart container
```

`make e2e` builds the fixture wasm with `stellar-cli` and runs the suite against
`https://soroban-testnet.stellar.org`. It is the equivalent of:

```sh
cd e2e/contracts && stellar contract build    # once, produces the fixture wasm
cd ../.. && go test -tags e2e -v ./e2e/...
```

`make e2e-local` builds the same wasm, starts a local `stellar/quickstart`
container, runs the identical scenarios against it, and removes the container
afterwards even if the tests fail. It needs Docker as well as `stellar-cli`.

The suite requires a reachable Soroban RPC that answers `getNetwork`,
`getHealth` and `getLatestLedger`, plus either a reachable friendbot or an
already-funded `SOROAUTH_FUNDER_SEED`. `make e2e` also requires `stellar-cli`
and the Rust toolchain needed to build the fixture contracts. At the end of a
run, the suite reports completed and skipped scenario counts. The
exact-expiration scenario may skip only when the transaction cannot be included
at that exact ledger; if every scenario is skipped, the test command exits
non-zero.

## Choosing a network

The suite is not compiled for one network: `SOROAUTH_RPC_URL` selects the RPC,
and the passphrase, protocol version and friendbot endpoint are read from the
network the RPC reports rather than assumed. The same scenarios run against
testnet, a local quickstart, or anything else that speaks Soroban RPC.

| Variable                 | Effect                                                                                                                                      |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `SOROAUTH_RPC_URL`       | The RPC to use. Defaults to `https://soroban-testnet.stellar.org`.                                                                          |
| `SOROAUTH_FUNDER_SEED`   | Secret seed of an already-funded account that creates the test accounts by transfer. When set, funding never touches friendbot.             |
| `SOROAUTH_FRIENDBOT_URL` | Overrides the friendbot URL. Otherwise the network's own advertised one is used, falling back to testnet's only for a testnet-like network. |

Whatever URL is used is verified with live `getNetwork`, `getHealth` and
`getLatestLedger` calls before anything relies on it, and the passphrase,
protocol version and chosen funding path are logged at the start of the run.

### A local network

A local quickstart runs the standalone network, whose passphrase is
`Standalone Network ; February 2017` and whose root account is fixed (derived
from that passphrase), so every machine has the same funded account.
`make e2e-local` uses the network's root account as the funder:

- The container is started and waited on by `e2e/quickstart.sh`, which blocks
  until the RPC answers `getNetwork`; the root secret seed is read back from the
  container's own startup log rather than hard-coded.
- `SOROAUTH_FUNDER_SEED` is set to that seed, so test accounts are funded by a
  `CreateAccount` transfer from the root account and friendbot is never called.
  This is the path a local network needs when friendbot is disabled, and it is
  what makes a local run reproducible offline.
- A local quickstart does not deploy the native XLM Stellar Asset Contract,
  which every scenario that moves XLM through a SAC needs, so `make e2e-local`
  deploys it (`e2e/quickstart.sh deploy-native-asset`) before the run. A public
  network already has one, which is why this step is local-only.
- A local network may run a different protocol version than testnet (currently
  28 locally). The suite reports the version it found and does not assume parity
  with testnet, so a protocol change shows up in the log rather than as a
  signing failure.

Every account is generated at runtime. No key is read from disk, written to
disk, or committed. Nothing here touches mainnet.

A full run takes roughly three minutes, most of it waiting for ledgers to close.
A local run is faster, since ledgers close every few seconds rather than every
five.

## What each scenario proves

| ID  | Scenario                                | What it proves                                                                                                                                                                                    |
| --- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A   | Legacy `SOROBAN_CREDENTIALS_ADDRESS`    | An entry on the legacy arm, signed by soroauth, is accepted by the host.                                                                                                                          |
| B   | CAP-71 `SOROBAN_CREDENTIALS_ADDRESS_V2` | The address-bound arm is accepted. The test reports whether simulation returned V2 directly or whether `UpgradeToV2` was needed.                                                                  |
| C   | `AccountMultiSigner`                    | A multi-key signature vector meets a 2-of-2 medium threshold on a classic account. This signer has no JS equivalent, so the golden vectors cannot cover it; this is its proof.                    |
| D   | CAP-71 delegated signers                | A `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` entry with a `Void` top-level signature and two G-account delegates is accepted, so a contract account authenticates purely through its delegates. |
| E   | The host rejects what it should         | The same flow with a delegate the account never registered is refused by the contract's `__check_auth` with `UnknownDelegate`.                                                                    |
| F   | Session keys, in window                 | A CAP-71 delegates entry whose only delegate is a G-account session key, inside the ledger window the `session-keys` contract stored for it, is accepted.                                         |
| G   | Session keys, expired                   | The same flow pointed at a key whose window has closed is refused with the contract's own `SessionExpired` (error 4), on the contract's clock.                                                    |
| H   | M-of-N, exactly M                       | A 2-of-3 `threshold-account` is authorized by exactly two signed delegates, so `AuthorizeAll` does not have to sign every delegate for the account to accept.                                     |
| I   | M-of-N, M-1                             | The same account with one signed delegate is refused with the contract's `InsufficientSignatures` (error 3).                                                                                      |
| J   | Passkey (P-256) wallet                  | A custom account that verifies an ES256 (secp256r1) signature over the authorization payload accepts an entry signed through `NewPasskeySigner` and `Secp256r1SignatureScVal`.                    |
| K   | Passkey, bad signature                  | The same wallet and transfer with a corrupted P-256 signature is refused by the host's own `secp256r1` verification, reported as `Error(Crypto, InvalidInput)`, "failed secp256r1 verification".  |
| L   | Expired signature, rejected             | An entry signed with `signatureExpirationLedger` in the past is refused with `Auth` / `InvalidInput`, "signature has expired".                                                                    |
| M   | Expiration ledger itself, accepted      | An entry submitted at exactly its `signatureExpirationLedger` is accepted, proving the host's bound is inclusive. Skips rather than fails if the exact ledger cannot be hit.                      |
| N   | Nonce replay, first submission          | A valid entry is accepted, consuming its nonce.                                                                                                                                                   |
| O   | Nonce replay, second submission         | A second envelope carrying the same signed entry — same address, same nonce — is refused with `Auth` / `ExistingValue`, "nonce already exists for address".                                       |
| P   | Nonce replay, fresh-nonce control       | A new entry with a fresh nonce is accepted after the replay rejection, proving the account is not broken.                                                                                         |
| Q   | Three-level delegate tree               | A tree three delegate levels deep (A -> B -> C -> D), chained through modular accounts, is accepted; the submitted envelope is decoded back to observe its shape and the leaf signature verifies. |

Several tests exist only to stop the accepting ones passing for the wrong
reason:

- **`TestScenarioCRejectsASingleSignature`** signs with one key against a
  threshold of two and requires the host to refuse. Without it, scenario C would
  pass just as happily against an account whose threshold was never raised, and
  would prove nothing about multisig.
- **Scenario E asserts the specific contract error code**, not merely that the
  transaction failed. This matters: an earlier version of the test passed while
  the transaction was actually running out of instructions before `__check_auth`
  was ever reached. Asserting `ContractCode 1` is what makes it prove the thing
  it claims.
- **Scenarios G and I assert the contract's error code** for the same reason,
  and neither is satisfied by "the transaction failed". They also keep the
  accepting halves honest: F proves a window is honoured only because G proves
  the same window is enforced, and H proves partial signing works only because I
  proves a shortfall is caught.
- **Scenario L and M are two halves of one rule.** M proves the expiration
  ledger itself is still valid, and L proves the ledger after it is not. L alone
  would leave the inclusive bound unobserved; M alone would not show the bound
  is enforced. M skips, with a message, when the exact ledger cannot be hit.
- **Scenario O asserts the host's nonce error, not merely a failure**, and P is
  its control: without P, a rejection for any unrelated reason (a broken
  account, a malformed entry) would look like replay protection working.
- **Scenario Q decodes the submitted envelope** and asserts the observed tree is
  three delegate levels deep, rather than trusting that the tree it built was
  the tree that went out.
- **Scenario K asserts the host's own error, and keeps the key constant.** It is
  satisfied only by a `Crypto` failure whose message names the `secp256r1`
  verification. The credential public key it submits is the registered one and
  only the low bit of `s` is flipped, so the refusal is the signature check and
  not the wallet's own `UnknownKey` comparison — a test that swapped the key
  would pass while proving something else.

## How a scenario works

CAP-71-01 needs two simulation passes, and the tests follow that:

1. **Simulate in record mode.** The host reports which addresses must authorize
   the call, and hands back unsigned authorization entries.
2. **Sign with soroauth.** For A, B and C this is `AuthorizeAll`. For D and E
   the recorded entry is first wrapped with `WithDelegates`, then each delegate
   is signed with `AuthorizeEntry` and `ForAddress`. F and G use the same flow
   as D; H and I sign only the M delegates they attach, and never touch the rest
   of the registered set, which is the partial-signing case.
3. **Simulate in enforce mode**, carrying the signed entries, so the resource
   fee accounts for the signatures that are actually there.
4. **Assemble** — the Go SDK has no `assembleTransaction`, so the simulated
   `SorobanTransactionData` is attached to the operation explicitly and its
   resource fee set from the simulation's `minResourceFee`.
5. **Sign the envelope** as the payer and submit, then poll until it resolves.

The scenarios that are meant to be rejected skip step 3. That pass would fail
locally for the very reason under test, which would only show that simulation
agrees with the host; the point is to put the transaction in front of the real
host and watch it be refused there, after fees. Because the recording pass never
executed `__check_auth`, its instruction count is too low, so those submissions
are given extra instruction headroom — otherwise they run out of budget before
reaching the rejection under test.

The default headroom is sized for a refusal a _contract_ returns as an error,
where the work the recording pass missed is one `__check_auth` call. Scenario
K's refusal is not that: the host's own `secp256r1` verification fails, and
paying for that verification is most of the transaction's cost, so at the
default multiplier the submission exhausted its budget while the host was
escalating the trap and the host reported the budget failure instead of the
P-256 one. `scenarioSpec.headroom` lets one scenario override the multiplier,
and K's value is measured rather than guessed: at the default 6 the recording
pass supplied 2,774,226 instructions against a measured requirement of
3,454,949.

The credential arm reported for each scenario is read back off the envelope that
was actually submitted, by decoding it again, rather than assumed from what the
test meant to build.

## Files

The tests are split by role rather than kept in one file:

| File                        | Holds                                                                                                                                                                                                                            |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `harness_test.go`           | Connecting to and verifying the RPC, funding accounts, building, simulating, assembling, submitting and polling; decoding the submitted envelope's credential arm; rendering host failures and extracting their error details.   |
| `transfer_test.go`          | The native-SAC `transfer(from, to, amount)` operation builder and small `ScVal`/`ScAddress` helpers.                                                                                                                             |
| `runner_test.go`            | The single scenario runner and its parameter table: the record/sign/enforce/assemble/submit shape shared by every scenario, plus decoded-entry and signed-entry diagnostics.                                                     |
| `runner_regression_test.go` | The deterministic regression fixture for rejection-path resource headroom.                                                                                                                                                       |
| `scenario_ab_test.go`       | Scenarios A and B, including the V2 route decision.                                                                                                                                                                              |
| `scenario_c_test.go`        | Scenario C, the multisig account setup, and the single-signature control.                                                                                                                                                        |
| `scenario_de_test.go`       | Scenarios D and E and the delegates flow that wraps, signs per address, and submits. Scenarios F to I call the same flow.                                                                                                        |
| `scenario_fghi_test.go`     | Scenarios F to I: the two session-key scenarios and the two threshold scenarios, each asserting the contract's own error code where it expects a refusal.                                                                        |
| `scenario_jk_test.go`       | Scenarios J and K: the passkey-wallet flow, the P-256 credential key, and the signer built from `NewPasskeySigner` with `SignSecp256r1` and `Secp256r1SignatureScVal`.                                                           |
| `deploy_test.go`            | Uploading a fixture's wasm, instantiating it with that fixture's constructor arguments, and funding a contract with XLM. Holds the `ScVal` encoders the fixtures' constructors need.                                             |
| `network.go`                | The network decisions — classifying the passphrase, resolving the RPC and friendbot URLs, choosing the funder seed and picking the results file — kept out of the build-tagged files so a normal `go test ./...` exercises them. |
| `network_test.go`           | Unit tests for those decisions, the only e2e-related tests that run without the tag and without a network.                                                                                                                       |
| `quickstart.sh`             | Starts, queries and stops the local quickstart container `make e2e-local` runs against, and deploys the native asset contract a fresh local network lacks.                                                                       |
| `results_test.go`           | `TestMain` and the writer that produces `RESULTS.md` (testnet) or `RESULTS.local.md` (any other network) from a complete run.                                                                                                    |

## The fixture contracts

Five contracts in the workspace, plus one separate source fixture, each exist to
exercise a narrow authentication or policy path. None is audited or
feature-complete; do not deploy them to mainnet or use them as smart-account
starting points. See [Contract Fixtures](../docs/FIXTURES.md) for the paths each
one exercises and the limits of its test coverage.

- **`contracts/modular-account`** carries no signature of its own and authorizes
  purely by forwarding to CAP-71 delegated signers. Scenarios D and E.
- **`contracts/session-keys`** registers session keys, each valid only inside
  its own ledger window. Scenarios F and G.
- **`contracts/threshold-account`** requires M of its N registered signers
  before it authenticates anything. Scenarios H and I.
- **`contracts/policy-account`** enforces per-period spending limits by
  inspecting invocation arguments within `__check_auth`.
- **`contracts/passkey-wallet`** registers a P-256 (secp256r1) credential public
  key at construction and verifies an ES256 signature over the authorization
  payload inside `__check_auth`. Scenarios J and K.
- **`contracts/social-recovery`** exercises guardian-authorized signer rotation
  after a timelock. It is not in the contract workspace and has no live e2e
  scenario; its narrower coverage is described in the fixture guide.

Workspace fixtures have unit tests: `cargo test -p modular-account`,
`cargo test -p session-keys`, `cargo test -p threshold-account`,
`cargo test -p policy-account`, and `cargo test -p passkey-wallet`.

### The two clocks in the session-key fixture

Two different ledgers can invalidate a session-key authorization, and two
different pieces of code check them:

- The entry's own `signature_expiration_ledger` is checked by the **host**, in
  `verify_and_consume_nonce`, which runs only _after_ the contract's
  `__check_auth` has returned `Ok` (rs-soroban-env-host 27.0.1,
  `src/auth.rs:2492-2515` and `:2586-2602`).
- The session window is checked by the **contract**, inside `__check_auth`,
  against `env.ledger().sequence()`.

`delegatesFlow` sets `signature_expiration_ledger` roughly a thousand ledgers
ahead, so the host's check is not what refuses scenario G: the refusal is the
contract's, on the contract's clock, and the test asserts that contract error
code. The protocol binds the two clocks to nothing but the order they run in,
and `signature_expiration_ledger` is the only one of them a third party can
verify from the submitted entry alone.

### Why the threshold fixture counts attached delegates

`CustomAccount::get_delegated_signers` returns `Vec<Address>`, not the
signatures (soroban-sdk 27.0.6, `src/custom_account.rs:274`), so the contract
counts the delegates **attached** to the entry and then calls `delegate_auth`
for each, which is where the host checks that each one actually signed. A
present but wrong signature therefore fails there and is never counted as one of
the M. The count cannot be inflated by repeating an address either: the host
rejects duplicate or unsorted delegates before the contract runs
(rs-soroban-env-host 27.0.1, `src/auth.rs:2204-2217` and `:2092-2127`).

## RESULTS.md

`RESULTS.md` is written by a run, never by hand. It is only written when all
twelve scenarios ran in the same invocation, so it cannot be a partial record of
a single-scenario run. It carries the date, the network and protocol version,
and for every scenario the transaction hash, the ledger, the credential arm
observed on the submitted envelope, an explorer link, and the raw host error
verbatim where there was one.

Only a **testnet** run writes `RESULTS.md`: it is the evidence of record, the
file the README's testnet claims point at. Any other network — a local
quickstart, a futurenet — writes `RESULTS.local.md` instead, so a local
iteration can never overwrite the committed evidence with a run nobody agreed
to. The file also says which it is, and which network it came from.

Whether a result is labelled "accepted" or "rejected as expected" comes from the
scenario's own `ExpectRejection` field, not from a list of IDs in the writer, so
a new rejection scenario cannot be labelled "accepted" by forgetting to add it
somewhere.
