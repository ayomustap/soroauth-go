# soroauth

[![ci](https://github.com/soroauth/soroauth-go/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/soroauth/soroauth-go/actions/workflows/ci.yml)
[![go-stellar-sdk@main](https://github.com/soroauth/soroauth-go/actions/workflows/ci-sdk-main.yml/badge.svg?branch=main)](https://github.com/soroauth/soroauth-go/actions/workflows/ci-sdk-main.yml)
[![Go reference](https://pkg.go.dev/badge/github.com/soroauth/soroauth-go.svg)](https://pkg.go.dev/github.com/soroauth/soroauth-go)
[![Go report card](https://goreportcard.com/badge/github.com/soroauth/soroauth-go)](https://goreportcard.com/report/github.com/soroauth/soroauth-go)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Status](https://img.shields.io/badge/status-unaudited-orange)](SECURITY.md#status-of-this-library)

soroauth builds, signs and inspects Soroban authorization entries in Go. When a
contract calls `require_auth()` on an address that is not the transaction's
source account, the transaction has to carry a signed
`SorobanAuthorizationEntry` for that address — and the signature is not over the
entry, but over a `HashIdPreimage` whose shape depends on which credential arm
is in use. The Go SDK ships all of those XDR types and none of the code that
builds or signs those preimages. soroauth is that code, for all three address
credential arms: legacy `SOROBAN_CREDENTIALS_ADDRESS`, CAP-71
`SOROBAN_CREDENTIALS_ADDRESS_V2`, and CAP-71
`SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` including nested delegate trees.

## Contents

- [Install](#install)
- [Common tasks](#common-tasks)
- [Container image](#container-image)
- [Verifying a release](#verifying-a-release)
- [CLI](#cli)
- [Quickstart](#quickstart)
- [The two-pass simulation requirement](#the-two-pass-simulation-requirement)
- [Credential types](#credential-types)
- [Protocol version support](#protocol-version-support)
- [Delegates](#delegates)
- [Expiration](#expiration)
- [CAP-85 / Protocol 28](#cap-85--protocol-28)
- [Differences from the JS SDK](#differences-from-the-js-sdk)
- [Remote signing over HTTP](#remote-signing-over-http)
- [Browser and WebAssembly](#browser-and-webassembly)
- [Proven on testnet](#proven-on-testnet)
- [FAQ](#faq)
- [Status](#status)
- [Contributing](#contributing)
- [License](#license)

## Install

```sh
go get github.com/soroauth/soroauth-go
```

The CLI:

```sh
go install github.com/soroauth/soroauth-go/cmd/soroauth@latest
```

Requires Go 1.25.0 or later, and `github.com/stellar/go-stellar-sdk` v0.7.3 or
later. As checked on 2026-10-17, the root module pins v0.7.3; which newer SDK
versions that promise covers, and how the pin moves, is stated in
[docs/sdk-support.md](docs/sdk-support.md).

## Common tasks

The same commands [CONTRIBUTING.md](CONTRIBUTING.md) uses are wrapped by the
Makefile, so there is one entry point for the local checks and the generated
artefacts:

```sh
make              # fmt, vet and test (the default)
make build        # build the CLI to bin/soroauth
make vectors      # regenerate testdata/vectors from the pinned JS SDK
make vectors-check # regenerate, then fail if the committed vectors changed
make e2e          # build the test contract and run the live testnet suite
make wasm-budget  # build the wasm core and fail if it is over its size ceiling
```

Every target fails loudly: `make fmt` exits non-zero if any file is not
gofmt-clean, and `make vectors-check` exits non-zero if regeneration changes a
committed vector. `make help` lists the targets.

## Container image

A container image is published on GHCR for every release tag, for CI systems
that need to sign an entry without installing a Go toolchain:

```sh
docker pull ghcr.io/soroauth/soroauth-go:v0.1.0   # or :latest for the newest release

docker run --rm -e SEED=SABC... ghcr.io/soroauth/soroauth-go:v0.1.0 \
  sign --entry <base64> --valid-until 1234567 --network testnet --secret-env SEED
```

The seed is passed the same way it is on the command line: a named environment
variable, read only by `--secret-env`, never a flag value. The image itself
never contains any key material, and nothing bakes a seed into a layer. That
said, an environment variable set on a running container is visible to anything
that can inspect that container (`docker inspect`, `/proc/<pid>/environ` from
the host, a sidecar with the same namespace), the same as it would be for any
other process — treat container secret injection with the same care you would
give a plain environment variable anywhere else. The image is built from
`Dockerfile` at the repository root by `.github/workflows/release.yml` on every
`v*` tag push, and that same release attests and signs the pushed image digest;
see [Verifying a release](#verifying-a-release).

## Verifying a release

Every release binary and the container image are signed and carry build
provenance, so a consumer can tell a real release from a convincing copy. The
provenance is GitHub's own, the signatures are keyless Sigstore, and the
commands below are the ones the workflows run against every published release —
not documentation written once and never executed.

For a `vX.Y.Z` tag the release attaches, per platform (`linux/amd64`,
`linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`):

- `soroauth-<os>-<arch>` (`.exe` on Windows) — the binary;
- `soroauth-<os>-<arch>[.exe].spdx.json` — its SPDX SBOM, scanned from that
  binary with syft;
- `soroauth-<os>-<arch>[.exe].sigstore.json` — a detached Sigstore bundle: the
  signature plus everything needed to check it (certificate, chain,
  transparency-log entry);
- `soroauth-image-digest.txt` — the digest of the image the release attested and
  signed.

Nothing here needs a key from either side. The signing certificate is issued
against the release workflow's OIDC identity from GitHub Actions, so there is no
long-lived key in CI to steal or rotate and no public key for a consumer to
distribute or pin — the identity policy _is_ the verification.

### Verifying a downloaded binary

```sh
# Once: cosign and the GitHub CLI. Install cosign from
# https://github.com/sigstore/cosign/releases, or:
go install github.com/sigstore/cosign/v3/cmd/cosign@latest
gh auth login   # gh attestation verify reads GitHub's API

tag=v0.2.0
gh release download "$tag" --repo soroauth/soroauth-go --dir release-assets
cd release-assets

# 1. The Sigstore bundle: this binary was signed by the release workflow, and
#    the certificate names the workflow at a tag under this repository.
cosign verify-blob \
  --bundle soroauth-linux-amd64.sigstore.json \
  --certificate-identity-regexp '^https://github.com/soroauth/soroauth-go/.github/workflows/release.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  soroauth-linux-amd64

# 2. Build provenance: GitHub's own record of which workflow, commit and
#    runner produced these bytes. No key on your side either.
gh attestation verify soroauth-linux-amd64 \
  --repo soroauth/soroauth-go \
  --signer-workflow soroauth/soroauth-go/.github/workflows/release.yml

# 3. The SBOM attestation, and that the attached SBOM file is the document
#    that was attested: both sides are canonicalised, then compared.
gh attestation verify soroauth-linux-amd64 \
  --repo soroauth/soroauth-go \
  --signer-workflow soroauth/soroauth-go/.github/workflows/release.yml \
  --predicate-type https://spdx.dev/Document/v2.3 \
  --format json --jq '.[0].verificationResult.statement.predicate' > /tmp/attested-sbom.json
jq -S . /tmp/attested-sbom.json > /tmp/attested-sbom.sorted.json
jq -S . soroauth-linux-amd64.spdx.json > /tmp/local-sbom.sorted.json
diff /tmp/attested-sbom.sorted.json /tmp/local-sbom.sorted.json
```

From a checkout of this repository, `scripts/verify-release.sh` runs all of the
above over a whole release — every binary, every SBOM and the image digest — and
`--tamper-demo` copies one verified binary, flips a single byte and requires
both checks to reject the copy, so a green run means the gate bites:

```sh
scripts/verify-release.sh --tag "$tag" --tamper-demo
```

### Verifying the container image

```sh
digest="$(cat soroauth-image-digest.txt)"
policy='^https://github.com/soroauth/soroauth-go/.github/workflows/release.yml@refs/tags/'

cosign verify \
  --certificate-identity-regexp "$policy" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "ghcr.io/soroauth/soroauth-go@${digest}"

gh attestation verify "oci://ghcr.io/soroauth/soroauth-go@${digest}" \
  --repo soroauth/soroauth-go \
  --signer-workflow soroauth/soroauth-go/.github/workflows/release.yml
```

Both commands address the digest, never `:latest` or `:$tag`: a tag can be moved
to different bytes between pulls, a digest cannot. The digest names a
single-platform manifest today; when the image becomes multi-arch it names a
manifest list instead and the commands above are unchanged.

### What a pass proves, and what it does not

A pass proves, for the bytes you hold:

- the signature in the bundle was made with a certificate whose subject is
  `https://github.com/soroauth/soroauth-go/.github/workflows/release.yml@refs/tags/<tag>`
  and whose issuer is GitHub Actions' OIDC service, and that the signature is in
  Sigstore's public transparency log — so the signer is this repository's
  release workflow on that tag, and the bytes are the ones it signed;
- GitHub's attestation store holds a signed statement, written by a workflow run
  in `soroauth/soroauth-go`, binding the artifact's digest to the commit, the
  workflow file and the runner that produced it;
- for the image, the same two things about the digest the release names;
- the SBOM attached to the release is the document that was attested — the bytes
  are compared, not just the presence of an attestation.

It does not prove:

- that the code is correct or its dependencies benign. Provenance says where
  bytes came from, not what they do; the audit status is in
  [SECURITY.md](SECURITY.md);
- SLSA Build L3, and nothing here should be quoted as such. Attestations minted
  on a GitHub-hosted runner are non-forgeable from outside GitHub: a consumer
  can tell that this repository's release workflow, on this commit, on a
  GitHub-hosted runner produced the bytes. But the workflow is not
  cryptographically isolated from the build the way L3 requires, and no
  independent party has reproduced the build. It is real provenance; it is not a
  level;
- that the release is the newest one, or that the tag on GitHub still points at
  the commit the attestation names. Pin the digest or the binary you verified
  rather than re-resolving a tag later;
- anything about releases published before this scheme: they carry no
  `.sigstore.json` assets. `scripts/verify-release.sh` fails on them and says
  why, and `.github/workflows/verify-release.yml` skips them with a message
  instead of pretending they verified.

The same commands run in CI: the `verify-release` job of
`.github/workflows/release.yml` verifies the release it just published before
the run can be green, and `.github/workflows/verify-release.yml` re-verifies the
newest release that carries bundles every week, so a bundle that stops verifying
fails a run instead of going unnoticed.

## CLI

Every subcommand that produces output accepts `--json` to emit a single JSON
object (or, for `tree`, either the JSON report or one of its two text renderings
— see below) on stdout. On success the object carries the result fields; on
failure it carries an `error` field. Nothing else is written to stdout in JSON
mode, so scripts can safely pipe the output to `jq` without stripping usage
text. `tui` is the one exception: it is an interactive terminal program, not
something a script drives, so it has no `--json` mode.

| subcommand      | success fields                                                                                                                              | failure field                                       |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `payload`       | `preimage`, `payload`                                                                                                                       | `error`                                             |
| `sign`          | `signed_entry`                                                                                                                              | `error`                                             |
| `simulate`      | `entries` (with `operation_index`, `entry_index`, `arm`, `entry` each), `min_resource_fee`, `transaction_data`, `latest_ledger`, `envelope` | `error`                                             |
| `submit`        | `hash`, `status`, `ledger`, `arm` (plus `result_xdr` and `diagnostic_events` when the transaction failed)                                   | `error`                                             |
| `delegates`     | `wrapped_entry`                                                                                                                             | `error`                                             |
| `inspect`       | (the `EntryInfo` struct — this was already `inspect`'s only output; `--json` is accepted for consistency and does not change it)            | `error`                                             |
| `diff`          | `identical`, `payload_changed`, `signatures_changed`, `stale_signatures`, `changes`, `summary`                                              | `error`                                             |
| `verify`        | the report: `credential_type`, `address`, `valid_until_ledger`, `verified`, and `nodes` with a `verdict` per credential node                | `error`                                             |
| `tree`          | (the `EntryInfo` struct, same shape as `inspect`; without `--json` it prints an ASCII or DOT rendering instead)                             | `error`                                             |
| `doctor`        | `checks`, `ok`                                                                                                                              | (checks carry their own `pass`/`detail`; see below) |
| `cross-compile` | `target`, `size`, `sha256` (one per line)                                                                                                   | `error`                                             |
| `completions`   | `shell`, `script`                                                                                                                           | `error`                                             |
| `man`           | `format`, `page`                                                                                                                            | `error`                                             |
| `wasm-budget`   | `size`, `budget`, `exceeded`, and optional `previous_size` and `delta`                                                                      | `error`                                             |

### Worked invocation — JSON output

```sh
# Pipe subcommands together without intermediate shell variables:
./soroauth delegates --entry <base64> --valid-until 1234567 --delegate GAAAA... --json |
  ./soroauth sign --entry - --valid-until 1234567 --network testnet --secret-env SEED --json

# What would this signer have to sign?
SEED=SABC... ./soroauth payload \
  --entry <base64> --valid-until 1234567 --network testnet --json |
  jq -r .payload

# Sign and get the entry back as JSON
SEED=SABC... ./soroauth sign \
  --entry <base64> --valid-until 1234567 --network testnet \
  --secret-env SEED --json |
  jq -r .signed_entry

# Wrap an entry with delegates, JSON out
./soroauth delegates \
  --entry <base64> --valid-until 1234567 \
  --delegate GAAAA... --delegate GBBBB... --json |
  jq -r .wrapped_entry

# Inspect an entry (output is JSON either way) and pick fields out of it
./soroauth inspect --entry <base64> |
  jq -r '"\(.credential_type) \(.address) expires=\(.valid_until_ledger)"'
```

### Simulate and submit — from a simulated transaction to a landed one

`payload`, `sign`, `inspect` and the rest work on an entry somebody already has.
`simulate` and `submit` are the two ends that produce one and send it.

`simulate` runs the record pass: it takes a transaction envelope, asks the host
which addresses must authorize the call, and prints every entry the host
recorded with its operation index, entry index and credential arm. The arm is
reported as the host recorded it, not as the caller asked for it, because
`--use-upgraded-auth` is best-effort. It also prints — and carries in its JSON
as `envelope` — the input envelope with the recorded entries attached, which is
the thing the next step needs: signing a bare entry produces a bare entry, and
getting it back into a transaction by hand is the part of the two-pass flow
people get wrong.

`submit` takes that envelope back, runs the enforcing pass so the resource fee
covers the signatures, signs the envelope with the seed named by `--secret-env`
(never a flag value), sends it, and polls to a terminal state. The transaction
hash is printed the moment the RPC accepts it and before the poll, so a poll
that times out still leaves something to look up.

```sh
export SOROAUTH_RPC_URL='https://soroban-testnet.stellar.org'

# 1. Record: which addresses must authorize this call?
soroauth simulate --entry unsigned-tx.b64 --json | tee recorded.json

# 2. Sign the entries. The authorizer's seed, not the payer's.
SEED_AUTHORIZER=SABC... soroauth sign \
  --entry "$(jq -r .envelope recorded.json)" \
  --valid-until 1234567 --network testnet --secret-env SEED_AUTHORIZER \
  --for GAAAA... > signed-tx.b64

# 3. Enforce, sign the envelope as the payer, send and poll.
SEED_PAYER=SABC... soroauth submit \
  --entry signed-tx.b64 --network testnet --secret-env SEED_PAYER
```

`submit` refuses to send a transaction whose address entries are unsigned — the
host would refuse it on-chain and the fee would be spent anyway — naming the
address that is missing a signature. `--allow-unsigned` overrides that for the
one case this tool cannot judge: a custom account deciding its own signature
shape. A delegates entry's Void top-level node is not a refusal, because
CAP-71-01 permits it when every delegate authenticates.

Neither subcommand signs the entries for you, and neither picks an endpoint:
`--rpc-url` or `$SOROAUTH_RPC_URL` is required, because a simulation or a
submission is about to authorize value on a specific chain.

### Batch mode — many entries in one run

`inspect`, `verify` and `sign` take `--entries <file|->`, and `diff` takes
`--before-entries`/`--after-entries`, so a list of entries costs one process
instead of one process per line. The input is one base64 authorization entry per
line (`-` reads stdin; blank lines are skipped). An envelope is never a batch
line, because one envelope carries several entries — select them first.

Every result is labelled with its 1-based position, and one bad line never ends
the run: `entry N:` on stdout for a result, `entry N: <why>` on stderr for a
failure, and the exit code is the first failure's. With `--json` the report is a
single array — `{"entry": N, "result": ...}` or `{"entry": N, "error": "..."}` —
so it composes with `jq`:

```sh
# Inspect a list; one labelled report per entry
./soroauth inspect --entries entries.b64

# Verify a whole batch, then list only the entries that did not verify
./soroauth verify --entries entries.b64 --network testnet --json |
  jq -r '.[] | select(.result.verified != true) | .entry'

# Sign a batch; the signed entries come back in input order
SEED=SABC... ./soroauth sign --entries entries.b64 \
  --valid-until 1234567 --network testnet --secret-env SEED --json |
  jq -r '.[].result.signed_entry' > signed.b64

# What changed across a batch? The two files are compared in order
./soroauth diff --before-entries before.b64 --after-entries after.b64
```

`sign` is all-or-nothing, the same rule the library's `AuthorizeAll` enforces:
if any line cannot be signed, no signed output is written at all — the report is
only the failures — because a half-signed batch must never read as a complete
one. `diff` pairs the Nth non-blank lines of its two files and refuses files
whose entry counts differ. No batch path echoes an entry into output or logs: a
caller sees the position, never the bytes.

### Tree — render a delegate tree

`inspect` reports an entry's structure as JSON; `tree` renders the same
structure — the delegates-arm tree in particular — as something a person can
read at a glance, either for a terminal or for embedding in docs.

```sh
# Terminal-readable, indented ASCII
./soroauth tree --entry <base64>

# Graphviz DOT, for docs
./soroauth tree --entry <base64> --format dot | dot -Tsvg -o tree.svg

# Structured, same shape as "inspect"
./soroauth tree --entry <base64> --json
```

```
GTOP (unsigned)
├── GA... (signed)
│   └── GA... (unsigned)
└── GB... (unsigned)
```

One address appearing at more than one nesting level is legal under CAP-71-01
(the same key delegating twice in one tree), and `tree` never merges those
occurrences into a single node: each is printed in its own position, with its
own signed/unsigned state, so a repeated address never reads as one node that
somehow got signed twice.

### Verify — check an entry's signatures without submitting it

Every other check is about structure. `verify` is about the signatures: it
rebuilds the payload from the entry as it stands — including the expiration the
entry stores — and checks each signature against it, so an entry that was
tampered with after signing, or signed over a different expiration than it
carries, is caught before it is submitted rather than after fees are paid.

```sh
./soroauth verify --entry <base64> --network testnet

# Accept the Void top-level node a delegates-only account legitimately has
./soroauth verify --entry <base64> --network testnet --allow-unsigned

# JSON, for scripting
./soroauth verify --entry <base64> --network testnet --json |
  jq -r '.nodes[] | "\(.address) \(.verdict)"'
```

Each credential node is one of four verdicts: `verified`, `unsigned`, `invalid`
(a well-formed signature that does not verify), or `cannot_check`. The exit code
is 4 unless every node verified (with `--allow-unsigned` tolerating unsigned
nodes), so a green result means exactly what it says.

**What it cannot do.** Only a classic account signature — the built-in vector
holding one `{public_key, signature}` map — can be decided offline. A custom
account's signature is whatever its `__check_auth` accepts, and only the
contract can say whether a given value is valid, so any other shape is reported
as `cannot_check` and never as `verified`. Whether the key that signed is
actually a signer of the account, and whether enough signers signed to meet its
threshold, are account-state questions this command cannot see and does not
claim to answer. A green result is evidence that the signatures on the entry
commit to it; it is not a promise the transaction will succeed. The full
statement of what a green result does and does not guarantee is in
[docs/verification-limits.md](docs/verification-limits.md).

### Diff — what changed between two entries, and what it invalidated

Reviewing a re-signed, upgraded or wrapped entry otherwise means comparing two
base64 blobs. `diff` reports the difference, and separates the changes that
invalidate signatures from the ones that do not — which is the whole point,
because in a plain field list a changed expiration and a changed signature are
both one line, and only the first is fatal.

```sh
./soroauth diff --before <base64> --after <base64>

# JSON, for scripting
./soroauth diff --before <base64> --after <base64> --json |
  jq -r '.summary, (.stale_signatures // [])[]'
```

Under CAP-71-01 every credential node of an entry commits to the **same**
payload, and that payload holds the credential arm, the nonce, the expiration
ledger, the invocation tree and — on the address-bound arms — the address. So
moving the expiration by one invalidates every signature in a delegate tree at
once, without touching a single signature byte (delegate addresses elided here;
the real output prints them in full):

```
PAYLOAD CHANGED and 4 signatures carried over unchanged: they are no longer valid

stale signatures (committed to the old payload):
  credentials.delegates[G…1]
  credentials.delegates[G…2]
  credentials.delegates[G…2].nested[G…3]
  credentials.delegates[G…4]

changes:
  ! expiration     credentials.signatureExpirationLedger
      1234567 -> 1234568

  ! marks a change inside the signed payload
```

The delegate tree itself is **not** in the payload, so adding or removing a
delegate changes the entry without invalidating anyone's signature, and the
report says so rather than crying wolf.

The exit code is 4 when the payload moved and at least one signature was carried
over unchanged, and 0 otherwise — including when the entries simply differ. A
difference is not a failure; an invalidated signature is. In the library this is
`DiffEntries`, which returns the same report as a value.

### Doctor — check the local environment for common first-run problems

Most first-run problems are environmental — an unreachable RPC endpoint, a
mistyped secret variable name, a Go toolchain older than this module needs — and
the error from `sign` or `payload` does not say so. `doctor` checks three things
and reports each as pass or fail: never printing a secret, only whether it is
set. It also reports which configuration file was loaded and which precedence
layer (`flag`, `env`, `file`, or `default`) supplied each resolved setting.

```sh
# Human-readable
./soroauth doctor --rpc-url https://soroban-testnet.stellar.org --secret-env SEED

# JSON
./soroauth doctor --rpc-url https://soroban-testnet.stellar.org --secret-env SEED --json
```

```json
{"checks":[{"name":"go toolchain","pass":true,"detail":"go1.25.4"},{"name":"network","pass":true,"detail":"https://soroban-testnet.stellar.org reachable (HTTP 405)"},{"name":"secret env: SEED","pass":true,"detail":"SEED is set"}],"config":{"file_source":"none","values":[{"key":"network","value":"","source":"default"},{"key":"rpc_url","value":"https://soroban-testnet.stellar.org","source":"flag"},{"key":"secret_env","value":"SEED","source":"flag"},{"key":"format","value":"","source":"default"}]},"ok":true}
```

`--secret-env` is optional; when omitted, that check is skipped rather than
reported as a failure. `--rpc-url` defaults to the public testnet RPC, and any
HTTP response — including a non-2xx status — counts the network check as
passing, since it proves DNS, TCP and TLS all worked; only a transport-level
error (DNS failure, connection refused, timeout) fails it. Exit code is 0 when
every check passes, 1 if any fails.

### Configuration file and precedence

Subcommands that accept `--network`, `--rpc-url`, `--secret-env`, or `--format`
can read defaults from a JSON configuration file (`--config <path>`,
`$SOROAUTH_CONFIG`, or `$XDG_CONFIG_HOME/soroauth/config.json` /
`~/.config/soroauth/config.json`). A missing default config file is not an
error; an explicit `--config` path that does not exist, or any unparseable file,
is an error.

Values resolve in strict precedence order:

1. `flag` — explicit command-line flag (`--network`, `--rpc-url`,
   `--secret-env`, `--format`)
2. `env` — environment variable (`SOROAUTH_NETWORK`, `SOROAUTH_RPC_URL`,
   `SOROAUTH_SECRET_ENV`, `SOROAUTH_FORMAT`)
3. `file` — JSON configuration file (`network`, `rpc_url`, `secret_env`,
   `format`)
4. `default` — built-in default

```json
{
  "network": "testnet",
  "rpc_url": "https://soroban-testnet.stellar.org",
  "secret_env": "SOROAUTH_SEED",
  "format": "json"
}
```

No secret value may be stored in the configuration file. `secret_env` accepts
only the POSIX name of an environment variable (`[A-Za-z_][A-Za-z0-9_]*`); any
Stellar strkey seed (`S...`), hex key, PEM block, or secret-bearing field name
(`secret`, `seed`, `private_key`) is refused before the command runs, and the
refused value is never echoed.

### External signer (`--signer-cmd`)

`soroauth sign` can delegate signing to an external helper executable via
`--signer-cmd <path>` (with `--signer-timeout`, default `10s`) instead of
`--secret-env`. The CLI invokes the helper once per target credential node and
speaks the same JSON protocol on stdin/stdout that `remote/protocol.go` defines
for HTTP:

- **stdin (`remote.Request`)**:
  `{"version": 1, "address": "G...", "preimage": "<base64 HashIdPreimage>", "payload": "<64-char hex sha256>"}`
- **stdout (`remote.Response`)**: `{"signature": "<base64 XDR ScVal>"}` or
  `{"error": "<reason>"}`

Passing the full `preimage` alongside `payload` lets the helper inspect and
recompute the SHA-256 digest or display the invocation details to a user before
approving. The CLI validates the returned `signature` as a well-formed,
non-placeholder `ScVal` (and verifies classic account `ScvVec` signatures over
the payload) before writing it into the entry. Helper non-zero exit, timeout,
and malformed output are reported as distinct errors, and no secret environment
variables are inherited by the helper process.

### Cross-compile — build binaries for multiple targets

The `cross-compile` subcommand builds soroauth for any GOOS/GOARCH pair. It is
useful for creating release artifacts or verifying that the codebase compiles
cleanly on all targets.

```sh
# Human-readable output for the default matrix (all 5 release targets)
./soroauth cross-compile

# Build only linux/amd64 and windows/amd64, emit JSON (one object per line)
./soroauth cross-compile --targets linux/amd64,windows/amd64 --json

# Write binaries to a directory instead of just printing metadata
./soroauth cross-compile --targets linux/amd64 --output-dir ./dist
```

Sample JSON output:

```json
{"target":{"goos":"linux","goarch":"amd64","binary":"soroauth"},"size":4190368,"sha256":"1d214924a4717228e2c0b694c4b4d3c3077c29ed036d9b00805e431b4a6e8433"}
{"target":{"goos":"windows","goarch":"amd64","binary":"soroauth.exe"},"size":4308992,"sha256":"d241d7f7ab8ff20215fbb254abc4eb71643408f62cffc3c0989e552801ae75e4"}
```

On error, JSON mode emits a single object to stdout with an `error` field (and
nothing to stderr):

```json
{"target":{"goos":"invalid","goarch":"target","binary":""},"error":"invalid target \"invalid/target\": unknown GOOS/GOARCH"}
```

#### CI cross-compilation matrix

The CI workflow (`.github/workflows/ci.yml`) includes a `cross-compile` job that
runs on every push and PR. It builds for the five release targets in parallel
with a 5-minute timeout per platform:

- `linux/amd64`
- `linux/arm64`
- `darwin/amd64`
- `darwin/arm64`
- `windows/amd64`

The job is build-only (no tests, no artifacts uploaded) and runs a smoke test
(`./soroauth help`) on the native platform to verify the binary runs. Failures
are named by platform in the workflow UI.

To reproduce a CI failure locally:

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o soroauth-arm64 ./cmd/soroauth
./soroauth-arm64 help
```

### Completions — shell completion for subcommands and flags

`soroauth completions --shell bash|zsh|fish` prints a completion script for that
shell on stdout. The scripts complete the subcommands, each subcommand's flags,
every enumerable flag value (`--shell`, `--format` on `payload`, `inspect`,
`verify`, `diff`, `tree`, and `man`, and `--network`'s three named shorthands
`testnet`, `futurenet`, `public` while still allowing literal passphrases), and
dynamic credential addresses (`--address`, `--delegate`) extracted from an
`--entry` already supplied on the command line; fish additionally shows each
flag's description in the tab menu. Dynamic address completion parses XDR only
and never executes entry contents or runs a signer. `--secret-env` is completed
by name only — the shells never see or complete a variable's value.

Install by shell:

```sh
# bash — for the current session only
source <(soroauth completions --shell bash)

# bash — for every future session
soroauth completions --shell bash > ~/.local/share/bash-completion/completions/soroauth

# zsh — write to a directory in $fpath, before compinit runs
soroauth completions --shell zsh > "${fpath[1]}/_soroauth"

# fish — fish loads this automatically in new shells
soroauth completions --shell fish > ~/.config/fish/completions/soroauth.fish
```

The scripts are generated from the same command/flag table the CLI parses, so a
flag added to a subcommand without updating the completions spec fails the test
suite (`TestSpecsMatchTheRealFlagSets`) rather than shipping a completion script
that silently omits it.

### Version — which build am I running?

`soroauth --version` prints the release tag, the commit and the Go toolchain
version the binary was built with:

```sh
soroauth --version
```

```
soroauth v0.2.0
commit: 9f1c3ab
built: 2026-09-28T11:04:02Z
go: go1.25.4
```

The three build fields are stamped at build time with `-ldflags`. The release
workflow passes the tag, the commit and the run's date
(`.github/workflows/release.yml`); `make build` stamps the checkout it was built
from. A binary built without either — a plain `go build`, or a `go install` —
reports `dev`, `unknown` and `unknown` rather than empty strings, so a bug
report that says `dev` is telling you it did not come from a release. The
toolchain line is read from the running binary (`runtime.Version()`), so it
cannot drift from the toolchain that produced it.

### Man page

`soroauth man` prints a man page for the CLI, and `--out` writes it to a file
for a packager (Homebrew, apt, an RPM) to install:

```sh
# Read it without installing anything
soroauth man --out /tmp/soroauth.1 && man /tmp/soroauth.1

# What a packaging step writes
soroauth man --out soroauth.1
```

`make man` builds the CLI and writes `bin/soroauth.1`. The page is generated
from the same command/flag table the completion scripts come from, so it cannot
document a flag the binary does not accept, and it carries no build timestamp:
two builds of the same source emit identical bytes. Every `v*` release attaches
`soroauth.1` alongside the binaries.

### Wasm budget — fail the build when the wasm core outgrows its ceiling

`soroauth wasm-budget` measures the compiled js/wasm signing core and exits
non-zero if it is larger than its budget. The core is downloaded by a browser,
so its size is worth failing on rather than noticing after a release.

```sh
# Measure the built artifact against the default 7 MiB ceiling.
soroauth wasm-budget --out wasm/dist/soroauth.wasm

# Build and measure in one step, with a budget of your own.
soroauth wasm-budget --build-cmd ./wasm/build.sh --budget 6500000

# Report the delta against the last release's size.
soroauth wasm-budget --prev-size 6204087

# Machine-readable, for CI.
soroauth wasm-budget --json
```

```json
{
  "size": 6211959,
  "budget": 7340032,
  "exceeded": false,
  "previous_size": 6204087,
  "delta": 7872
}
```

The default budget is 7 MiB (7340032 bytes), a ceiling set above the size the
build actually produces (6211959 bytes, measured with go1.25.4 on darwin/arm64)
rather than an aspiration. A binary exactly at the budget passes; only one
strictly larger fails. `--prev-size` is optional, and a negative `delta` means
the artifact shrank.

Stdout carries only the result, on the over-budget path too — the diagnostic
goes to stderr — so `soroauth wasm-budget --json | jq .exceeded` works whether
the build passed or failed. `make wasm-budget` runs it against
`wasm/dist/soroauth.wasm` after building both the CLI and the core.

### Release workflow

The project uses a GitHub Actions workflow (`.github/workflows/release.yml`)
that runs on version tags (`v*`). It:

1. Regenerates the golden vectors from the pinned JS SDK and fails if they drift
   (the same check that runs on every push).
2. Builds the CLI for `linux/amd64`, `linux/arm64`, `darwin/amd64`,
   `darwin/arm64`, `windows/amd64`, scans an SPDX SBOM from each binary, attests
   each binary's build provenance and SBOM, and keyless-signs each binary into a
   detached Sigstore bundle.
3. Builds and pushes the container image, attests and keyless-signs the pushed
   digest, and records that digest for the release.
4. Creates a GitHub Release whose notes are extracted from `CHANGELOG.md` for
   the tagged version.
5. Attaches the built binaries, an SBOM and a Sigstore bundle per binary, the
   generated man page (`soroauth.1`) and the image digest, then verifies the
   published release with `scripts/verify-release.sh` — including the tamper
   demo that proves the checks reject modified bytes. See
   [Verifying a release](#verifying-a-release).

To cut a release:

```sh
# Update CHANGELOG.md with the new version's entries
git tag v0.2.0
git push origin v0.2.0
```

The workflow will refuse to publish if the golden drift check fails, so a
release is only created when the library is provably byte-identical to the
reference implementation. It is only green when the release it just published
verifies, so a release whose signatures or attestations are broken stays red
rather than being announced.

## Quickstart

Simulation tells you which addresses must authorize a call. Hand those entries
to soroauth, and put the signed ones back on the operation:

```go
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
```

This example is compiled by CI as `internal/readmesnippets/quickstart.go` — see
[Verifying README snippets](CONTRIBUTING.md#verifying-readme-snippets-compile).

Source-account entries pass straight through untouched, so you can hand over
everything simulation returned without sorting by arm first.

## The two-pass simulation requirement

The Quickstart comment
`// then re-simulate in enforce mode, assemble, sign, submit` is doing a lot of
work. CAP-71-01 needs **two** simulation passes, and skipping the second is the
single most common way to produce a transaction that builds, signs — and fails
on-chain after fees are paid.

**Pass 1 — record mode.** The transaction carries no signatures yet, so the host
_recording_ what auth would be needed: it hands back the unsigned authorization
entries and prices resources without having executed any account contract's
`__check_auth`. Signing happens here.

**Pass 2 — enforce mode.** Signing the entries changes what the transaction
costs: a signature ScVal is real memory the host has to hold and check. The
transaction is re-simulated in `AuthModeEnforce` carrying the **signed**
entries, and it is this pass's resource footprint and fee that the submitted
transaction must carry.

**What goes wrong without pass 2.** The envelope assembled from pass 1 carries
the recording pass's resource fee, which is too small once the signatures are
on. The submission is then rejected on-chain for exceeding its resource budget —
a fee-bounded failure that happens _after_ fees and after your signers have
approved the entry, and one that reads like a signature problem when it is
really a pricing problem.

**The enforcing pass is also a free pre-flight check.** It executes
`__check_auth` with your real signatures, so a wrong signature shape, a
mis-targeted address, or an unsigned node the contract insists on is caught
locally instead of on-chain.

One deliberate exception: a submission that is _meant_ to be rejected skips the
enforcing pass, which would fail locally for the very reason under test. See
[e2e/README.md](e2e/README.md) for how the rejection scenarios handle that.

After the enforcing pass, assemble explicitly — the Go SDK has no
`assembleTransaction` equivalent to the JS SDK's, so the simulated
`SorobanTransactionData` is attached to the operation by hand:

```go
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
```

This example is compiled by CI as `internal/readmesnippets/twopass.go` — same
verification story as the Quickstart above.

A `Soroban RPC integration helpers` package (see `docs/ISSUE_BACKLOG.md`) is
planned to lift this flow — both passes, assembly, the resource fee — into one
correct, reusable call. Once it exists, this section will link it as the
preferred alternative to hand-rolling assembly.

Until then, `adapters/walletsdk` enforces this same discipline in code: it
refuses to hand back a submittable envelope unless the enforcing pass ran.

## Credential types

| Arm                                          | Value | Preimage variant                                                                            | Address in the signed bytes? |
| -------------------------------------------- | ----- | ------------------------------------------------------------------------------------------- | ---------------------------- |
| `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT`         | 0     | none — the envelope signature covers it                                                     | n/a                          |
| `SOROBAN_CREDENTIALS_ADDRESS`                | 1     | `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION` (9)                                                   | no                           |
| `SOROBAN_CREDENTIALS_ADDRESS_V2`             | 2     | `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS` (10)                                     | yes                          |
| `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` | 3     | `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS` (10), bound to the **top-level** address | yes                          |

The legacy arm is defined by CAP-46-11; V2 and the delegated-signer arm by
CAP-71-01 and CAP-71-02. V2 binds the signer's address into the signed payload,
which closes a narrow replay case: one key shared across several accounts,
combined with a contract that does not itself bind the address into its
arguments.

`UpgradeToV2` converts an unsigned legacy entry to V2. You may need it:
simulation can return either arm, and the RPC's `UseUpgradedAuth` flag is
best-effort — it affects only the recording auth modes and is ignored by
protocol versions whose host cannot emit AddressV2.

## Protocol version support

Each arm's CAP states the protocol version it was introduced in; a network
running an older protocol cannot emit or accept that arm at all. The
introduction versions below are from the cited CAPs, checked on 2026-10-17.

| Arm                                          | Introduced in | Source    |
| -------------------------------------------- | ------------- | --------- |
| `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT`         | Protocol 20   | CAP-46-11 |
| `SOROBAN_CREDENTIALS_ADDRESS`                | Protocol 20   | CAP-46-11 |
| `SOROBAN_CREDENTIALS_ADDRESS_V2`             | Protocol 27   | CAP-71-01 |
| `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` | Protocol 27   | CAP-71-02 |

`ArmProtocolVersion` carries this same table in code
(`TestArmProtocolVersionMatchesTheReadme` fails if the two drift), for a caller
that wants to check it programmatically before pointing soroauth at an older
network. soroauth itself makes no RPC call and does not check a live network's
protocol version — the table exists so the requirement is visible before a
confusing on-chain failure, not to enforce it.

## Delegates

Under CAP-71-01 an account can authorize through delegated signers instead of
signing itself. Every node in the tree — the account and every delegate at every
depth — signs **one** payload, bound to the top-level address.

```go
wrapped, err := soroauth.WithDelegates(entry, validUntil,
    []soroauth.Delegate{
        {Address: d1},
        {Address: d2, Nested: []soroauth.Delegate{{Address: d3}}},
    }, nil) // nil top-level signature → ScvVoid, which CAP-71-01 permits
if err != nil {
    return wrapped, err
}

for _, kp := range []*keypair.Full{k1, k2, k3} {
    wrapped, err = soroauth.AuthorizeEntry(ctx, wrapped,
        soroauth.NewEd25519Signer(kp), validUntil, passphrase,
        soroauth.ForAddress(kp.Address()))
    if err != nil {
        return wrapped, err
    }
}
```

This example is compiled by CI as `internal/readmesnippets/delegates.go` — see
[Verifying README snippets](CONTRIBUTING.md#verifying-readme-snippets-compile).

Each delegates array is sorted by the XDR encoding of the address and checked
for duplicates within that level, as CAP-71-01 requires; the same address at two
_different_ levels is allowed, and one `AuthorizeEntry` call fills every node
carrying that address.

Because every node commits to the same payload, the expiration is fixed once any
node is signed: signing another node at a different `validUntilLedger` would
leave the entry's signatures disagreeing, so soroauth refuses it.

Replacing one delegate's signature needs `AllowResign`, scoped to that
delegate's address so the override does not also apply to a different call
touching another node in the same entry:

```go
resigned, err := soroauth.AuthorizeEntry(ctx, wrapped, soroauth.NewEd25519Signer(k1),
    validUntil, passphrase, soroauth.ForAddress(d1), soroauth.AllowResign(d1))
```

This example is compiled by CI as `internal/readmesnippets/allowresign.go` — see
[Verifying README snippets](CONTRIBUTING.md#verifying-readme-snippets-compile).

`AllowResign()` with no arguments keeps its original, unscoped meaning: the
guard is lifted for whatever address that call targets. Naming one or more
addresses restricts it to those; a target outside the list still refuses with
`ErrAlreadySigned`. Either way, the expiration guard above is never lifted.

One consequence worth stating plainly: the delegates arm and V2 share the same
address-bound preimage, so the same address, nonce, invocation, expiration and
network produce an **identical payload** on both arms — golden vectors 3 and 6
show exactly that. Replay protection comes from the nonce, which the host
consumes; this is by design under CAP-71-01, not a defect.

`AuthorizeAll` applies every signer matching any node in the tree. It does not
fail when a delegate has no signer, because it cannot know the account's policy.

An unsigned node fails only if the account's `__check_auth` calls
`delegate_account_auth` for that address — the host then runs that delegate's
`__check_auth` with whatever signature the node carries (CAP-71-01, _Semantics →
`delegate_account_auth` function_), and an empty one is not something a
G-account delegate can authenticate with. The pattern the CAP recommends, and
the one soroban-sdk's `delegate_auth` documentation and this repo's e2e fixture
both follow, delegates to _every_ listed signer. So unless you know your
account's policy, treat an unsigned node as one that will fail: check the
per-node `Signed` flags from `Inspect` before submitting.

## Expiration

`ExpirationAfter(latestLedger, ledgers)` turns a lifetime into the absolute
ledger an entry must carry. Two things about that number, both read from the
host rather than inferred:

- **It is inclusive.** `verify_and_consume_nonce` rejects only when
  `ledger_seq > live_until_ledger`, so the expiration ledger itself is still
  valid. The JS SDK's doc comment describes the bound as exclusive; the host is
  the authority.
- **There is an upper bound this library cannot enforce.** The host also rejects
  anything above the network's `max_live_until_ledger`. That is a network
  setting, so it is deliberately not hard-coded here — a baked-in constant would
  silently become wrong. Read it from the network if you need the real ceiling.

Zero is refused: by the rule above it is already expired, not permissive.

A worked example: the RPC reports latest ledger 1000, which has already closed,
so a transaction built now lands in ledger 1001 at the earliest.
`ExpirationAfter(1000, 1)` returns 1001, which is accepted in ledger 1001 and
rejected from ledger 1002. `ExpirationAfter(1000, 0)` is refused, because 1000
has already passed. The same example, as a table, is in the `ExpirationAfter`
doc comment.

## CAP-85 / Protocol 28

This assessment was checked on 2026-10-17 and applies to the root module's
`github.com/stellar/go-stellar-sdk` v0.7.3 pin. That SDK version already
includes Protocol 28 XDR support: its
[changelog](https://github.com/stellar/go-stellar-sdk/blob/v0.7.3/CHANGELOG.md)
records CAP-85 and CAP-83 support in v0.7.0. The earlier statement that v0.7.3
predates Protocol 28 was incorrect.

Evidence:

- [CAP-85](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0085.md)
  introduces externally managed contract executables and adds their type to
  contract-creation authorization context. It does not add a Soroban credential
  arm or a signing-preimage variant, so soroauth's authorization preimage
  construction needs no CAP-85-specific change.
- The live testnet RPC's `getNetwork` response reported `protocolVersion: 29` on
  2026-10-17. The e2e transactions in [e2e/RESULTS.md](e2e/RESULTS.md) were
  recorded on 2026-10-17 against that network version; those results are a dated
  snapshot, not a promise about a future network state.
- The SDK pin is v0.7.3, and `go.mod` selects `go-xdr`
  v0.0.0-20260806060815-dc590f17552a. The authorization signing implementation
  is still covered by the pinned `@stellar/stellar-sdk@17.1.0` vectors; the live
  testnet evidence is recorded separately in the dated e2e results.

Re-check this assessment when the Go SDK pin changes or a later CAP changes
authorization-entry XDR or the signing preimage. A change to either requires a
new golden vector and, when protocol behavior changes, a live e2e run.

## Differences from the JS SDK

soroauth is proven byte-for-byte against `@stellar/stellar-sdk@17.1.0`, and
deviates from it in four deliberate ways.

- **A signature is only ever written to a node whose address matches the
  target** — `ForAddress`, or the signer's own `Address()`. The JS reference
  falls back to the top-level node when no target is given, even if the key
  belongs to someone else. soroauth returns `ErrNoMatchingCredentialNode`
  instead, because a signature on the wrong node is a transaction that pays fees
  and then fails.
- **No default write to the top-level node**, for the same reason.
- **The signer is never invoked when nothing matches.** The zero-match check and
  the already-signed check run _before_ signing, so a hardware wallet or remote
  signer is never asked to approve something that is about to be discarded.
- **`AccountMultiSigner`** has no JS equivalent. It signs for a classic account
  with several keys, sorted strictly ascending by raw public key and capped at
  20, which is what the host requires.

soroauth is also stricter in one place: wrapping or upgrading an entry that
already carries a signature returns `ErrAlreadySigned`, where JS silently
discards the old signature. The payload changes under both operations, so that
signature would no longer verify.

## Remote signing over HTTP

The `remote` package defines a small protocol for signing a payload over HTTP,
and ships a reference server plus a client that satisfies `soroauth.Signer`. The
point of the protocol is that the **preimage** is transmitted, not just the
digest, so the remote end can inspect the whole structure it is approving rather
than blind-signing a hash. The server recomputes SHA-256 of the preimage and
refuses a request whose payload does not match, and the client attaches its
context to the request so cancelling it aborts an in-flight call.

```go
server := remote.NewServer(soroauth.NewEd25519Signer(signerKey))
server.Approver = remote.LogApprover(os.Stderr) // record what is approved
http.Handle(remote.Path, server)

signer := remote.NewSigner("http://127.0.0.1:8080", signerKey.Address())
return soroauth.AuthorizeEntry(ctx, unsigned, signer, validUntil, network.TestNetworkPassphrase)
```

It is a reference, not a service: it has no authentication, holds no key store,
and does no rate limiting, so a real deployment must put those in front of it.
Nothing in the root module depends on `remote`.

## Browser and WebAssembly

The signing core builds for `js/wasm`, so a browser can derive the bytes it
signs instead of trusting a server for the payload. This is what makes passkey
signing possible without a round trip that hands over the preimage.

If you are integrating from a browser page, start with
[docs/browser.md](docs/browser.md): install, load, a minimal working snippet,
and the demo.

- The module lives in `cmd/soroauthwasm` and is built with `wasm/build.sh`. It
  exposes building a preimage, hashing it to a payload, writing an externally
  produced signature onto an entry, and a deterministic ed25519 path for tests.
- The `@soroauth/wasm` TypeScript wrapper (in `wasm/ts`) gives that surface real
  types, loads from bytes or a URL, and turns every failure into a thrown
  `SoroauthError` rather than a numeric code.
- `make wasm-check` proves the wasm build is byte-identical to the golden
  vectors; the package's own tests run under jsdom and against the real module.

The wrapper calls through to the same Go code as the native library, so there is
no second implementation of the signing logic to drift.

For the full passkey flow — browser ceremony, assertion verification, and what
is (and is not yet) proven — see [docs/passkeys.md](docs/passkeys.md). Replacing
hand-rolled signing code with soroauth — pattern mappings, the four differences
from the JS SDK, and how to verify the migration produced identical bytes — is
covered in [docs/migrating.md](docs/migrating.md). Choosing the right signer for
your threat model — in-memory, multisig, Vault, Ledger, KMS, remote, and passkey
signers — is covered in [docs/signers.md](docs/signers.md). For a sequential
three-party delegate handoff — including the shared-expiration rule — see
[docs/multi-party-signing.md](docs/multi-party-signing.md).

## Proven on testnet

Every claim below is backed by a transaction that exists on chain. Full detail,
including raw host errors, is in [e2e/RESULTS.md](e2e/RESULTS.md). These results
were recorded on 2026-10-17; the RPC reported protocol version 29 for that run.

| Scenario                                            | Result                  | Transaction                                                                                                                |
| --------------------------------------------------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Legacy `ADDRESS` accepted                           | accepted                | [`6d77c01a…`](https://stellar.expert/explorer/testnet/tx/6d77c01affa11766979ad905e68d32a61a6e3daa6a110096ce7bb4698376a182) |
| CAP-71 `ADDRESS_V2` accepted                        | accepted                | [`566dcdac…`](https://stellar.expert/explorer/testnet/tx/566dcdacee95e2e44646099b78de46208f1b1c2b18bc0c818dcdae2349d85661) |
| `AccountMultiSigner` meets a 2-of-2 threshold       | accepted                | [`9914176a…`](https://stellar.expert/explorer/testnet/tx/9914176a36dd314927aa830930a57c2bd85254a8bef659b1d88e13408a82459f) |
| One signature does **not** meet that threshold      | rejected, as it must be | [`5b0b49e7…`](https://stellar.expert/explorer/testnet/tx/5b0b49e75e958feff7152b359039996ca57f28ee371e2207633ec645a7faa6c6) |
| Delegated signers accepted, account itself unsigned | accepted                | [`5cd87e73…`](https://stellar.expert/explorer/testnet/tx/5cd87e7397b0936550875944d8f8df217ee75b438a5c706c31565c89cd2ccf2a) |
| An unregistered delegate is refused                 | rejected, as it must be | [`9afda479…`](https://stellar.expert/explorer/testnet/tx/9afda479a6b5bad8cdefd4c35956aaf2a1ba15e13f394b818a3db8d392f52fdd) |

The two rejection rows matter as much as the acceptances: they assert the host's
specific reason, so the accepting scenarios cannot be passing by accident.

Offline, the golden vectors generated by `@stellar/stellar-sdk@17.1.0` assert
that soroauth's preimage, payload hash and final signed entry are byte-identical
to the reference, and CI regenerates them on every push to catch drift. That
agreement is cross-checked by two other implementations: the Python
`stellar-sdk` v16.1.0 recomputes every vector's preimage and payload in CI
(`make parity`), and the Rust `stellar-xdr` v28.0.0 crate — the XDR
implementation the Soroban host itself uses — does the same
(`make parity-rust`). These parity pins were checked on 2026-10-17, so a bug
shared by the Go and JS implementations cannot hide in the vectors.

Fixed vectors only cover the cases someone thought of, so there is also a
differential fuzzing harness: `make differential` generates a random corpus of
structurally valid entries — every credentials arm, delegate trees of random
depth, sub-invocation trees, both nonce signs and the `int64` edges — and
requires the Go SDK v0.7.3, JS SDK v17.1.0 and Python `stellar-sdk` v16.1.0
references pinned on 2026-10-17 to agree on every payload. A divergence is a
release blocker, not a test flake. See
[testdata/differential/README.md](testdata/differential/README.md).

What that agreement does and does not establish — and what no offline suite can
rule out — is stated in one place in [docs/parity.md](docs/parity.md).

## FAQ

The questions this design invites — why there is no default write to the
top-level node, why `AuthorizeAll` succeeds with a delegate node unsigned, why
the expiration ledger is inclusive, whether the legacy arm is deprecated — are
answered with their sources in [docs/faq.md](docs/faq.md).

## Status

**v0.1.0. Unaudited.** The wire format is fixed by the protocol and pinned by
the golden vectors, but this library is new and has not been reviewed by anyone
outside its author. Read the code before you sign anything valuable with it.

## Contributing

Every document in the repository is listed, with one line on what it answers, in
[docs/README.md](docs/README.md).

See [CONTRIBUTING.md](CONTRIBUTING.md). Golden vectors are never edited by hand.
Security reports go through [SECURITY.md](SECURITY.md), not the issue tracker.
For questions and where to send each kind of report, see
[SUPPORT.md](SUPPORT.md).

The Markdown in this repository is link-checked by the
[`links` workflow](.github/workflows/links.yml) and spell-checked by the
[`spellcheck` workflow](.github/workflows/spellcheck.yml). Neither runs on pull
requests, which carry only the three checks the branch ruleset requires: both
run on push to `main`, on a weekly schedule, and on demand. A broken internal
link or a typo is therefore caught one commit after it lands rather than one
review before. External links are only reported, never failed, since a page
moving elsewhere is not a regression here.

## License

Apache-2.0. See [LICENSE](LICENSE). Source files carry no per-file header by
design; the reasoning is in
[CONTRIBUTING.md](CONTRIBUTING.md#no-per-file-license-headers). To cite the
project, use [CITATION.cff](CITATION.cff).
