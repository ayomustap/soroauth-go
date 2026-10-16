# soroauth explanation extension (reference)

A browser user asked to sign a Soroban authorization entry normally sees base64.
This extension shows them the entry's structure and the risk analyzer's findings
before they approve: the credential arm, the address, the nonce, the expiration,
the delegate tree, the invocation tree, and the analyzer's findings with its
documented limits.

It is a **reference implementation, not a product**: no store listing, no
telemetry, no update channel. It exists to show that the library already has
every piece needed to explain an entry at the point of decision — `Inspect`, the
risk analyzer, the tree renderers and the wasm build — with nothing assembling
them.

## What it is not

It reports **structure**, not meaning. It will tell you an entry authorizes
`transfer` on some contract with three arguments; it will not tell you what
transferring means, whether the arguments are reasonable, or whether the
contract is one you trust. That is a different project (`soroauth-explain`), and
this one links to it rather than duplicating it.

The disclaimer and the analyzer's limits
([`docs/analyzer-heuristics.md`](../../docs/analyzer-heuristics.md)) are part of
every rendered panel — not behind a toggle — so a UI cannot present the
structure as a safety verdict. A report with no findings says the heuristics
matched nothing, not that the entry is safe.

## Everything comes from the wasm core

`src/report.js` calls the wasm signing core — the same `inspect`, `analyze`,
`renderTree` and `renderInvocations` the library, the CLI and the other bindings
call (they are `soroauth.Inspect`, `soroauth.Analyze`, `DelegateTreeASCII` and
`InvocationTreeASCII`). Nothing here reimplements "what does this entry
authorize": a second implementation is a second thing that can be wrong.

| Path              | What it is                                                                              |
| ----------------- | --------------------------------------------------------------------------------------- |
| `src/core.js`     | Loads the wasm core and the typed wrapper (staged into `vendor/`).                      |
| `src/report.js`   | `buildReport(core, entryXdr, …)` — the report object, from the core. Pure, unit-tested. |
| `src/overlay.js`  | Renders a report and returns a decision; approves only on an explicit click.            |
| `src/injected.js` | Runs in the page's world and installs `globalThis.soroauthExplain`.                     |
| `src/content.js`  | Injects `injected.js` into matching pages.                                              |
| `src/popup.*`     | Paste an entry, see its structure.                                                      |
| `test/`           | The logic above, against the real wasm core.                                            |

## The gate

The passkey example (`examples/browser-passkey/`) calls
`globalThis.soroauthExplain.confirm(...)` — see its
[`explain-gate.js`](../../examples/browser-passkey/explain-gate.js) — after it
derives the payload and before it asks the authenticator to sign. When this
extension is installed, `injected.js` defines that global, so the user gets the
panel and must approve explicitly. With no extension installed the global is
absent and the demo proceeds unchanged.

A gate that is present but throws, declines, or resolves to anything other than
`true` is a refusal: an error in the extension can never silently downgrade to
signing anyway.

## Build and test

The extension vendors the wasm core and the typed wrapper from the repository
build; both are build output and are never committed. From the repository root:

```sh
./wasm/build.sh
(cd wasm/ts && npm ci && npm run build)
cd integrations/browser-extension && npm test
```

`npm test` stages `vendor/` and runs the Node check, which exercises the report,
the overlay (including that Escape rejects and only the approve button approves)
and the example's gate against the real wasm core and the committed golden
vectors.

## Loading it in a browser

Chrome/Chromium, MV3:

1. Build and stage as above (so `vendor/` exists).
2. `chrome://extensions` → enable **Developer mode** → **Load unpacked** →
   select this directory (`integrations/browser-extension`).
3. Open the [browser passkey example](../../examples/browser-passkey/) (served
   over `http://localhost`, which the manifest matches), start a signing flow,
   and the extension's panel appears before the authenticator is asked to sign.

The popup works with any entry: paste the base64 XDR and press **Explain this
entry**.

## Verification status

`npm test` runs in CI (`.github/workflows/ci-wasm.yml`) and covers the report,
the overlay's decision rules and the example's gate against the real wasm core.

**Not covered in CI:** the extension loading in a real browser — the manifest,
the content-script injection, and Go's runtime inside a page. CI has no browser,
the same limitation the passkey demo and `docs/browser.md` already state. If you
run it and it fails past the checks above, that is a bug worth filing.
