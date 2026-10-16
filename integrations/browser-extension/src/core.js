/**
 * Load the soroauth wasm signing core in an extension context.
 *
 * The core is the same `wasm/dist/soroauth.wasm` the package publishes, wrapped
 * by the same `@soroauth/wasm` typing surface — staged into `vendor/` by
 * `scripts/stage-wasm.mjs`. Nothing is reimplemented here; this only gets the
 * module instantiated.
 *
 * The Go runtime shim is installed as a classic script (it sets
 * `globalThis.Go`), and the wasm bytes are fetched from the extension's own
 * web-accessible URL. The result is memoised so a page that asks twice for an
 * explanation does not instantiate a second Go runtime.
 */

import { loadSoroauth } from "../vendor/index.js";

const WASM_EXEC_URL = new URL("../vendor/wasm_exec.js", import.meta.url);
const WASM_URL = new URL("../vendor/soroauth.wasm", import.meta.url);

let corePromise = null;

/** installGoRuntime loads Go's wasm_exec.js once, into globalThis.Go. */
function installGoRuntime() {
  if (globalThis.Go) return Promise.resolve(globalThis.Go);
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = WASM_EXEC_URL.href;
    script.onload = () => resolve(globalThis.Go);
    script.onerror = () => reject(new Error("soroauth: could not load wasm_exec.js"));
    (document.head ?? document.documentElement).append(script);
  });
}

/**
 * loadCore returns the typed signing-core API, loading it on first use.
 *
 * Throws when the wasm cannot be fetched or instantiated, so a caller surfaces
 * a failure instead of showing an empty report that looks like "nothing found".
 */
export function loadCore() {
  if (!corePromise) {
    corePromise = (async () => {
      const Go = await installGoRuntime();
      const response = await fetch(WASM_URL.href);
      if (!response.ok) {
        throw new Error(`soroauth: could not load the wasm core (HTTP ${response.status})`);
      }
      const wasm = new Uint8Array(await response.arrayBuffer());
      return loadSoroauth({ wasm, go: Go });
    })();
  }
  return corePromise;
}
