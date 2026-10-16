// Vendor the wasm signing core and the typed wrapper into this extension's
// `vendor/` directory.
//
// The extension is a set of plain ES modules loaded by a browser, so it cannot
// resolve the `@soroauth/wasm` package from node_modules and it must not carry
// a second copy of the signing logic. This copies the built artifacts instead:
//
//   * `wasm/dist/soroauth.wasm`      the core the other bindings use
//   * `wasm/dist/wasm_exec.js`       Go's runtime shim that matches it
//   * `wasm/ts/dist/*.js`            the typed wrapper (`@soroauth/wasm`)
//
// Both are build output, never committed (`vendor/` is gitignored), so the
// extension always runs the core built from the checkout in front of it.
//
// Build first, from the repository root:
//
//   ./wasm/build.sh
//   (cd wasm/ts && npm ci && npm run build)

import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const EXTENSION = resolve(HERE, "..");
const ROOT = resolve(EXTENSION, "..", "..");
const WASM_DIST = join(ROOT, "wasm", "dist");
const TS_DIST = join(ROOT, "wasm", "ts", "dist");
const VENDOR = join(EXTENSION, "vendor");

/** die prints a message and exits non-zero; a missing build is a real error. */
function die(message) {
  console.error(`stage-wasm: ${message}`);
  process.exit(1);
}

for (const [what, dir, hint] of [
  ["the wasm core", WASM_DIST, "./wasm/build.sh"],
  ["the typed wrapper", TS_DIST, "(cd wasm/ts && npm run build)"],
]) {
  if (!existsSync(dir)) die(`${what} is not built at ${dir}; run ${hint} first.`);
}

mkdirSync(VENDOR, { recursive: true });

// `wasm/build.sh` copies Go's runtime shim with its source mode, which is
// read-only; a plain copy would carry that mode into vendor/ and make the next
// run fail to overwrite it. Stage by reading and writing, writing 0644, and
// removing any previous copy first so a read-only one cannot block the write.
function stage(source, name) {
  const dest = join(VENDOR, name);
  rmSync(dest, { force: true });
  writeFileSync(dest, readFileSync(source), { mode: 0o644 });
}

for (const name of ["soroauth.wasm", "wasm_exec.js"]) {
  const source = join(WASM_DIST, name);
  if (!existsSync(source)) die(`${source} is missing; run ./wasm/build.sh.`);
  stage(source, name);
}

// The wrapper is a few ES modules (`index.js` imports `./errors.js` and
// `./types.js`); copying every .js keeps those relative imports working.
let staged = 0;
for (const name of readdirSync(TS_DIST)) {
  if (!name.endsWith(".js")) continue;
  stage(join(TS_DIST, name), name);
  staged += 1;
}
if (staged === 0) die(`no .js files in ${TS_DIST}; run (cd wasm/ts && npm run build).`);

console.log(`stage-wasm: staged the wasm core and ${staged} wrapper module(s) into ${VENDOR}`);
