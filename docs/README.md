# Documentation

This is the map. Every document in the repository is listed here with the
question it answers, so a newcomer does not have to guess which of the README,
the architecture note and the guides is the one they need. The repository root
[README](../README.md) links here, and the static documentation site generator
(`scripts/docsite`) reads this file as its single source of truth for
navigation.

## Start here

| Document                           | Answers                                                                                                    |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| [README](../README.md)             | What soroauth is, how to install it, and a 20-line quickstart for signing a simulated entry.               |
| [ARCHITECTURE](../ARCHITECTURE.md) | How the signing flow works, what each file is responsible for, and the CAP-71-01 delegate model.           |
| [CONTRIBUTING](../CONTRIBUTING.md) | How to set up, what the tests expect, the commit format, and what a pull request has to pass.              |
| [SECURITY](../SECURITY.md)         | How to report a vulnerability privately, what counts as critical, and the unaudited status of the library. |
| [SUPPORT](../SUPPORT.md)           | Where to ask questions, how issues are triaged, and what versions receive fixes.                           |
| [CHANGELOG](../CHANGELOG.md)       | What changed in each release.                                                                              |
| [faq](faq.md)                      | Why soroauth behaves as it does: the recurring design questions, each with its source.                     |

## Guides

| Document                                        | Answers                                                                                                            |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| [labels](labels.md)                             | What each complexity and area label means, who applies it, and who has the final say on complexity.                |
| [signers](signers.md)                           | Which signer to use for a given threat model, and what evidence backs each one.                                    |
| [passkeys](passkeys.md)                         | How to sign for a WebAuthn / passkey smart wallet, end to end.                                                     |
| [migrating](migrating.md)                       | How to replace hand-rolled auth-entry signing with soroauth and verify it produced identical bytes.                |
| [multi-party-signing](multi-party-signing.md)   | How three parties sign one delegate tree in sequence, and why the expiration cannot change once anyone has signed. |
| [verification-limits](verification-limits.md)   | What `soroauth verify` can and cannot establish offline.                                                           |
| [verification-service](verification-service.md) | How to run the HTTP verification service, and what it will and will not do.                                        |
| [sdk-support](sdk-support.md)                   | Which `go-stellar-sdk` versions are supported and how the pin moves.                                               |
| [browser](browser.md)                           | How to use soroauth from a browser page: installing and loading the wasm module, and the passkey flow.             |
| [fixture-quickstart](fixture-quickstart.md)     | How to run the e2e fixture contracts against a local Stellar quickstart container.                                 |
| [reproducibility](reproducibility.md)           | How to reproduce the released CLI binaries byte-for-byte from a tagged source checkout.                            |

## Reference

| Document                                      | Answers                                                                                                   |
| --------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| [analyzer-heuristics](analyzer-heuristics.md) | What each risk-analyzer heuristic catches and what it misses.                                             |
| [glossary](glossary.md)                       | What credential arm, preimage, payload, nonce and delegate ordering mean, with the CAP that defines each. |
| [security-analysis](security-analysis.md)     | How CodeQL and dependency review run in CI, and how static-analysis findings are triaged.                 |
| [FIXTURES](FIXTURES.md)                       | What each e2e fixture contract exercises, and why none is a product.                                      |
| [ISSUE_BACKLOG](ISSUE_BACKLOG.md)             | The written-up work that is not done yet; `WAVE9_BACKLOG.json` is the newer Wave's source of truth.       |
| [WAVE10_BACKLOG](WAVE10_BACKLOG.md)           | The Wave 10 issue backlog and acceptance criteria.                                                        |
| [diagrams](diagrams/README.md)                | The rendered signing-flow and delegate-tree diagrams, and their committed sources.                        |
| [UPSTREAM_PROPOSAL](../UPSTREAM_PROPOSAL.md)  | The proposal to add a minimal auth-entry signing helper to `go-stellar-sdk` itself.                       |

## Testing and evidence

| Document                                                                 | Answers                                                                                             |
| ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| [e2e/README](../e2e/README.md)                                           | What each live testnet scenario proves, and how the two-pass simulation flow works.                 |
| [e2e/RESULTS](../e2e/RESULTS.md)                                         | The transaction hashes and observed credential arms from a real testnet run.                        |
| [fuzzing](fuzzing.md)                                                    | How the fuzz targets run continuously, and how a crash becomes a committed regression seed.         |
| [soak](soak.md)                                                          | The reported batch signing soak run: what each round asserts, and how its tolerances were measured. |
| [parity](parity.md)                                                      | What agreement across implementations does and does not establish.                                  |
| [differential fuzzing](../testdata/differential/README.md)               | How random entries are checked across the Go, JS and Python implementations.                        |
| [frozen divergences](../testdata/differential/regressions/README.md)     | The regression corpus of cases the implementations once disagreed on.                               |
| [frozen vectors](../testdata/frozen/README.md)                           | The cross-version frozen vector set that must never be regenerated.                                 |
| [wasm parity regressions](../testdata/wasm-parity/regressions/README.md) | The regression corpus replayed against the js/wasm signing core.                                    |
| [Python parity](../testdata/parity-python/README.md)                     | How the vectors are recomputed with the Python `stellar-sdk`.                                       |
| [Rust parity](../testdata/parity-rust/README.md)                         | How the vectors are recomputed with the `stellar-xdr` crate the host itself uses.                   |

## Sub-project docs

These live next to the code they describe.

| Document                                                            | Answers                                                                       |
| ------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| [wasm](../wasm/README.md)                                           | What the js/wasm signing core exposes and how it is built.                    |
| [wasm/ts](../wasm/ts/README.md)                                     | How to use the `@soroauth/wasm` TypeScript wrapper.                           |
| [bindings/jvm](../bindings/jvm/README.md)                           | How to call soroauth from Java 22+ via Panama FFM.                            |
| [bindings/rust](../bindings/rust/README.md)                         | How to use the Rust `soroauth` crate.                                         |
| [examples](../examples/README.md)                                   | Overview of the runnable example programs in this repository.                 |
| [examples/browser-passkey](../examples/browser-passkey/README.md)   | How to run the browser demo that signs with a passkey and submits to testnet. |
| [examples/remote-signer](../examples/remote-signer/README.md)       | How to run the reference HTTP signing server and its client together.         |
| [examples/wallet-freighter](../examples/wallet-freighter/README.md) | How to inspect and verify an entry before signing with Freighter.             |
| [integrations/action](../integrations/action/README.md)             | How to verify Soroban authorization entries in GitHub Actions workflows.      |
| [integrations/grpc](../integrations/grpc/README.md)                 | How to run and call the gRPC verification service.                            |
| [server/openapi](../server/openapi/README.md)                       | The OpenAPI 3.0 specification and conformance check for `soroauth-server`.    |

## Repository meta

| Document                                                     | Answers                                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------------------ |
| [pull request template](../.github/pull_request_template.md) | What every pull request must state, including the wire-format checklist. |
| [CLAUDE.md](../CLAUDE.md)                                    | The original build specification for this project, kept for reference.   |
