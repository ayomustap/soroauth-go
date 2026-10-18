# Security policy

## Reporting a vulnerability

**Do not open a public issue.**

Report privately through GitHub Security Advisories:
[github.com/soroauth/soroauth-go/security/advisories/new](https://github.com/soroauth/soroauth-go/security/advisories/new).

Please include what you can: the affected version or commit, what an attacker
achieves, and a reproduction — a failing test, an entry that signs when it
should not, or a payload that differs from the reference implementation.

You will get an acknowledgement within a week. This is a small project with no
paid on-call, so that is a realistic commitment rather than an optimistic one.
If a fix is needed you will be credited in the advisory and the changelog unless
you ask otherwise.

## Context Cancellation Threat Model & Guarantees

**Threat Model:** Callers interacting with remote HSMs, hardware tokens, browser
extensions, or custom signing RPC services rely on context cancellation and
deadlines to bound latency and prevent goroutine or connection leaks. Without
strict context propagation and early cancellation checks in `Signer.Sign`, a
stalled remote peer, unresponsive hardware device, or slow network socket can
hang client goroutines indefinitely.

**Guarantees:**

- Every in-tree signer (`NewEd25519Signer`, `NewAccountMultiSigner`,
  `NewPasskeySigner`, and `SignerFunc`) inspects `ctx.Done()` before invoking
  cryptographic signing or downstream callbacks, failing immediately with
  `context.Canceled` or `context.DeadlineExceeded` if the context is terminated.
- Remote or hardware signer implementations must explicitly document any
  underlying inability to abort ongoing hardware operations or network requests
  if cancellation cannot interrupt the physical device or socket.

## Untrusted authorization entries

Authorization entries from simulations, RPC responses or callers are untrusted
input. For external base64 XDR, use `DecodeAuthorizationEntry`: it bounds the
decoded input to 1 MiB and nesting to 64 levels, while recursive operations
apply the same depth bound to already-decoded entries (`decode.go`). Treat a
limit refusal as an error, and apply your own size limits before constructing
large in-memory XDR values; these bounds do not validate application-specific
authorization policy. The adversarial regression cases are loaded by
`TestAdversarialRegressionsAreRefused` in `adversarial_test.go` from
`testdata/differential/regressions/`.

There is no separate hostile-input threat-model document to reconcile this note
against. [Static security analysis](docs/security-analysis.md) covers scanner
and dependency-review policy, not untrusted-entry handling.

## Scope

**Signature-correctness bugs are critical.** Anything in these categories should
be reported privately rather than filed publicly:

- A signature produced over the wrong payload: wrong preimage variant, wrong
  network id, wrong nonce, wrong expiration, or an address bound in that is not
  the one the caller named.
- A signature written onto a credential node other than the intended target, or
  onto a node whose address does not match.
- An entry accepted for signing that should have been refused — an
  already-signed node silently overwritten, a delegates array accepted out of
  order or with duplicates, an expiration that disagrees with signatures already
  on the entry.
- Any way to make the library emit an entry whose stored expiration differs from
  the expiration that was signed over.
- A secret reaching stdout, stderr, an error message, a log, or disk. The CLI
  accepts seeds only through a named environment variable and must never print
  one, including on error paths.
- Divergence from the golden vectors that is not a bug in the vectors.

### Remote Signer Retries and Threat Model

When using remote signers via `WithRetry`, the library provides jittered
exponential backoff and attempt capping strictly for transient transport errors.
Signature rejections (such as signature mismatches, invalid credentials, or
explicit refusals) are never retried to prevent hiding real failures or
exhausting HSM/KMS quotas.

**Threat model addressed:** Temporary network partitions, transient RPC/KMS
downtime, and connection resets during remote signing.

**Explicitly not addressed:** Protection against compromised remote signers,
malicious upstream KMS throttling due to high valid transaction volume, or
side-channel leakage across retry attempts.

Lower severity, still worth reporting privately if you are unsure: panics
reachable from untrusted input, and denial of service through malformed XDR.

**Out of scope:** the fixture contract in `e2e/contracts/` is test code, not a
product — it has no admin functions, no upgradability and no policy engine by
design, and findings about those absences are not vulnerabilities. Weaknesses in
the Stellar protocol itself belong with the
[Stellar Development Foundation](https://github.com/stellar/stellar-protocol/security/policy),
not here.

## Status of this library

**v0.1.0, unaudited.** No third party has reviewed this code. It is proven
byte-for-byte against `@stellar/stellar-sdk@17.1.0` by nine golden vectors, and
proven against a live host by the testnet scenarios in
[e2e/RESULTS.md](e2e/RESULTS.md) — but agreeing with a reference implementation
and being accepted by a host are not the same thing as having been audited, and
neither rules out a class of bug that both implementations share. What each
suite covers, and what none of them rule out, is stated in
[docs/parity.md](docs/parity.md).

Judge it accordingly before signing anything valuable with it, and read the
code.

## Supported versions

Only the latest release receives fixes. At v0.1.0 that is the only release.

## Retracting a release

A published version is never deleted and its tag is never moved. When a version
must not be used, it is retracted with a `retract` directive in `go.mod`. This
policy is decided now so that it does not have to be decided during an incident.

### When a version is retracted

A version is retracted if either of these is true:

- **It has a critical bug from the [Scope](#scope) list above.** For example, it
  signs over the wrong payload, writes a signature to the wrong credential node,
  accepts an entry it should refuse, stores an expiration that differs from the
  one it signed, or leaks a secret.
- **It was published by mistake.** For example, the tag points at the wrong
  commit, or the module does not build or cannot be imported.

A version is **not** retracted for an ordinary bug that cannot produce a bad
signature or expose a key, for a performance problem, or for missing support for
something newer. An older release refuses a credential arm it does not know with
`ErrUnsupportedCredentials` (`preimage.go`) instead of guessing. That is failing
closed, not a signing bug. Those problems are fixed in the next release as
usual.

### How it is done

1. The fix is released first, as a new version above every existing one. Only
   the latest release receives fixes (see
   [Supported versions](#supported-versions)), so the fix is never backported.
   The remedy for a retracted version is always to upgrade to the latest.
2. That release's `go.mod` retracts the bad version, with a one-line reason and
   the advisory ID when there is one:

   ```
   retract v0.1.0 // Signs over the wrong payload for delegate trees; GHSA-xxxx-xxxx-xxxx.
   ```

   Go reads retractions from the `@latest` version's `go.mod` only, which is why
   the directive ships in a new, higher version. `go mod edit -retract=v0.1.0`
   writes the directive. A range such as `retract [v0.1.0, v0.1.2]` covers
   several versions. If there is no fix yet, a new version can retract itself
   together with the bad one.

3. The root module and each module under `adapters/` have their own `go.mod`. A
   retraction applies only to the module whose `go.mod` declares it, so each
   affected module is retracted separately.

### How it is communicated

- A published GitHub Security Advisory, for anything in the [Scope](#scope)
  list. It names the affected and fixed versions.
- A `CHANGELOG.md` entry and release notes for the fixing release, saying which
  version is retracted and why.
- The reason in the `retract` comment, which the `go` command shows to anyone
  who checks for updates.

### What a retraction does to you

A retraction is a warning, not a removal. What follows is from the
[Go modules reference](https://go.dev/ref/mod#go-mod-file-retract), and each
point was reproduced with go1.25.4 against a local module proxy:

- **Existing builds keep working, silently.** A module that pins a retracted
  version still downloads and builds it. `go build` and `go run` print no
  warning. If you never check for updates, you will not notice. Watch the
  advisory, or run one of the checks below in CI.
- **Update checks show it.**

  ```
  $ go list -m -u all
  example.com/signer v0.1.0 (retracted) [v0.1.1]

  $ go list -m -retracted -f '{{.Version}} {{.Retracted}}' example.com/signer@v0.1.0
  v0.1.0 [Signs over the wrong payload; see advisory GHSA-xxxx.]
  ```

- **New resolution avoids it.** `go get`, `go mod tidy`, `@latest` and range
  queries skip retracted versions, and `go list -m -versions` hides them.
  Requesting the exact version still works, with a warning:

  ```
  $ go get example.com/signer@v0.1.0
  go: warning: example.com/signer@v0.1.0: retracted by module author: Signs over the wrong payload; see advisory GHSA-xxxx.
  go: to switch to the latest unretracted version, run:
  	go get example.com/signer@latest
  ```

To move off a retracted soroauth version, run
`go get github.com/soroauth/soroauth-go@latest`. Then re-sign anything you
signed with the retracted version that has not yet been submitted. The advisory
says which signatures are affected.

## Keys in this repository

Every test key in this repository is public and must never be funded on mainnet.
How they are derived, and the rules for adding one, are in
[Deterministic test keys](CONTRIBUTING.md#deterministic-test-keys). The e2e
tests do not use them: their keys are generated per run, funded by friendbot on
testnet, and never written to disk.
