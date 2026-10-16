// postinstall: use the prebuilt pair for this platform, or build it.
//
// A published package carries prebuilds/<platform>/ for every platform the
// release workflow built, so the common case is that this script does nothing.
// When there is no prebuild -- a fresh checkout of the repository, or a platform
// the release did not cover -- it tries a source build, which needs the Go
// toolchain for the shared library and a C toolchain for the addon.
//
// A failed source build is a warning, not a failed install: `npm install` in a
// project that never calls this binding should not break because a toolchain is
// missing. The binding itself still fails closed -- index.js throws a
// SoroauthError naming the missing artifact on the first call, so a caller can
// never mistake "not built" for "signed successfully".

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(HERE, "..");
const PLATFORM = `${process.platform}-${process.arch}`;
const PREBUILD_DIR = join(PACKAGE_ROOT, "prebuilds", PLATFORM);
const LIBRARY_NAME =
  process.platform === "darwin" ? "libsoroauth.dylib" : "libsoroauth.so";

const addon = join(PREBUILD_DIR, "soroauth.node");
const library = join(PREBUILD_DIR, LIBRARY_NAME);

if (existsSync(addon) && existsSync(library)) {
  console.log(`install: using the prebuilt binding for ${PLATFORM}`);
  process.exit(0);
}

console.log(`install: no prebuilt binding for ${PLATFORM}; attempting a source build`);
try {
  execFileSync(process.execPath, [join(HERE, "build.mjs")], {
    cwd: PACKAGE_ROOT,
    stdio: "inherit",
  });
} catch {
  console.warn(
    `install: could not build the binding for ${PLATFORM} (needs the Go toolchain, a C toolchain and node-gyp). ` +
      `Every call through this module will throw until it is built: run \`npm run build\` in ${PACKAGE_ROOT}.`,
  );
}
