// Build both halves of the Node binding for this machine:
//
//   1. the Go signing core as a C shared library, through bindings/c/build.sh;
//   2. the N-API addon over it, through node-gyp.
//
// Both land in prebuilds/<platform>/ so the layout a published package ships is
// the layout a local build produces -- there is no "works here, not there" gap,
// and index.js has exactly one place to look.
//
// The Go half is skipped when the repository's C ABI build script is absent
// (the case for a package installed from a tarball), which is why the library is
// staged separately from the addon rather than assumed.

import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(HERE, "..");
const REPO_ROOT = resolve(PACKAGE_ROOT, "..", "..");
const PLATFORM = `${process.platform}-${process.arch}`;
const PREBUILD_DIR = join(PACKAGE_ROOT, "prebuilds", PLATFORM);
const C_ABI_BUILD = join(REPO_ROOT, "bindings", "c", "build.sh");

if (process.platform === "win32") {
  console.error(
    "build: this binding loads the Go shared library with dlopen, which this repository does not support on Windows.",
  );
  process.exit(1);
}

const LIBRARY_NAME =
  process.platform === "darwin" ? "libsoroauth.dylib" : "libsoroauth.so";

mkdirSync(PREBUILD_DIR, { recursive: true });

// --- the Go shared library -------------------------------------------------

if (existsSync(C_ABI_BUILD)) {
  console.log(`build: compiling the C ABI into ${PREBUILD_DIR}`);
  execFileSync("sh", [C_ABI_BUILD, PREBUILD_DIR], {
    cwd: REPO_ROOT,
    stdio: "inherit",
  });
} else {
  console.log(
    "build: no bindings/c/build.sh (installed from a tarball); expecting a prebuilt library",
  );
}

const library = join(PREBUILD_DIR, LIBRARY_NAME);
if (!existsSync(library)) {
  console.error(`build: ${library} is missing; the Go toolchain is required`);
  process.exit(1);
}

// --- the N-API addon -------------------------------------------------------

const require = createRequire(import.meta.url);
let nodeGyp;
try {
  nodeGyp = require.resolve("node-gyp/bin/node-gyp.js");
} catch {
  console.error(
    "build: node-gyp is not installed; run `npm install` in this directory first",
  );
  process.exit(1);
}

console.log(`build: compiling the addon with node-gyp (node ${process.versions.node})`);
execFileSync(process.execPath, [nodeGyp, "rebuild"], {
  cwd: PACKAGE_ROOT,
  stdio: "inherit",
});

const built = join(PACKAGE_ROOT, "build", "Release", "soroauth.node");
if (!existsSync(built)) {
  console.error(`build: node-gyp produced no ${built}`);
  process.exit(1);
}
const staged = join(PREBUILD_DIR, "soroauth.node");
copyFileSync(built, staged);

console.log(
  `build: wrote ${staged} (${statSync(staged).size} bytes) and ${library} (${statSync(library).size} bytes)`,
);
