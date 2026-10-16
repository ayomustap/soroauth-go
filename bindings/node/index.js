"use strict";

/**
 * @soroauth/node — the soroauth signing core over its C ABI, for Node
 * backends that cannot run the wasm build.
 *
 * The addon (src/addon.c) dlopens the Go shared library (bindings/c) and every
 * call is a string-in, string-out hop across that boundary returning the ABI's
 * JSON envelope. This module parses the envelope and turns a failure into the
 * typed error its `kind` names (lib/errors.js), so the Go sentinels' own
 * distinctions survive into JavaScript.
 *
 * Nothing is reimplemented here, which is what makes the golden-vector replay
 * (test/vectors.test.mjs) meaningful: the bytes this binding emits are produced
 * by the same Go code path as every other binding.
 */

const fs = require("node:fs");
const path = require("node:path");

const errors = require("./lib/errors.js");

/** The shared library's file name on this platform. */
function nativeLibraryName() {
  if (process.platform === "darwin") return "libsoroauth.dylib";
  if (process.platform === "win32") return "libsoroauth.dll";
  return "libsoroauth.so";
}

/** platformKey is the `<os>-<arch>` directory a prebuild lives in. */
function platformKey() {
  return `${process.platform}-${process.arch}`;
}

/** findAddon returns the built `.node` addon, or null. */
function findAddon() {
  const candidates = [
    path.join(__dirname, "prebuilds", platformKey(), "soroauth.node"),
    path.join(__dirname, "build", "Release", "soroauth.node"),
    path.join(__dirname, "build", "Debug", "soroauth.node"),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

/** findLibrary returns the Go shared library for this platform, or null. */
function findLibrary() {
  const name = nativeLibraryName();
  const candidates = [
    path.join(__dirname, "prebuilds", platformKey(), name),
    path.join(__dirname, "lib", platformKey(), name),
    path.join(__dirname, "lib", name),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

/** parse turns an ABI envelope into its fields, or throws the typed error. */
function parse(envelopeJson, operation) {
  let envelope;
  try {
    envelope = JSON.parse(envelopeJson);
  } catch (cause) {
    throw new errors.SoroauthError(
      `soroauth: ${operation}: the native library returned invalid JSON`,
      "ERROR",
    );
  }
  if (!envelope || envelope.ok !== true) {
    throw errors.from(envelope);
  }
  return envelope;
}

/**
 * load wires the addon to a shared library and returns the typed API.
 *
 * The paths default to whatever `prebuilds/` or a local build provided; pass
 * `libraryPath`/`addonPath` to point at something else (a test double, or a
 * library built outside the package).
 */
function load(options = {}) {
  const addonPath = options.addonPath ?? findAddon();
  if (addonPath === null) {
    throw new errors.SoroauthError(
      "soroauth: the native addon is not built; run `npm run build` (needs node-gyp and a C toolchain) or install a published package",
      "ERROR",
    );
  }
  const addon = require(addonPath);

  const libraryPath = options.libraryPath ?? findLibrary();
  if (libraryPath === null) {
    throw new errors.SoroauthError(
      `soroauth: no shared library for ${platformKey()}; run \`npm run build\` (needs the Go toolchain) or install a published package`,
      "ERROR",
    );
  }
  addon.loadLibrary(libraryPath);

  return {
    /** The ABI version string, e.g. "soroauth-c-0.1.0". */
    version: () => addon.version(),

    /** Build the preimage and payload for an address-credential entry. */
    preimage: (entry, validUntilLedger, networkPassphrase) => {
      const envelope = parse(
        addon.preimage(entry, validUntilLedger, networkPassphrase),
        "preimage",
      );
      return { preimageXdr: envelope.preimageXdr, payloadHex: envelope.payloadHex };
    },

    /** Hash an already-built preimage (base64 XDR) to its 32-byte payload, hex. */
    payload: (preimageXdr) => parse(addon.payload(preimageXdr), "payload").payloadHex,

    /** Write an externally produced signature ScVal onto every matching node. */
    writeSignature: (
      entry,
      validUntilLedger,
      networkPassphrase,
      forAddress,
      signatureScval,
    ) =>
      parse(
        addon.writeSignature(
          entry,
          validUntilLedger,
          networkPassphrase,
          forAddress,
          signatureScval,
        ),
        "writeSignature",
      ).entryB64,

    /** Sign with a 32-byte ed25519 seed (hex): the deterministic path. */
    authorizeWithSeed: (
      entry,
      validUntilLedger,
      networkPassphrase,
      seedHex,
      forAddress = "",
    ) =>
      parse(
        addon.authorizeWithSeed(
          entry,
          validUntilLedger,
          networkPassphrase,
          seedHex,
          forAddress,
        ),
        "authorizeWithSeed",
      ).entryB64,

    /**
     * Sign with one or more 32-byte ed25519 seeds (hex, comma-separated). Two
     * or more seeds build an AccountMultiSigner: signatures are sorted strictly
     * ascending by public key and more than the host's 20-signature cap is
     * refused with `TooManySignatures`.
     */
    authorizeWithSeeds: (
      entry,
      validUntilLedger,
      networkPassphrase,
      seedsCsv,
      forAddress = "",
    ) =>
      parse(
        addon.authorizeWithSeeds(
          entry,
          validUntilLedger,
          networkPassphrase,
          seedsCsv,
          forAddress,
        ),
        "authorizeWithSeeds",
      ).entryB64,

    /** The entry's structure (`soroauth.EntryInfo`). */
    inspect: (entry) => JSON.parse(parse(addon.inspect(entry), "inspect").infoJson),

    /** The risk analyzer's findings. */
    analyze: (entry, currentLedger = 0) =>
      JSON.parse(parse(addon.analyze(entry, currentLedger), "analyze").findingsJson),

    /** The invocation tree, ASCII. */
    renderInvocations: (entry) =>
      parse(addon.renderInvocations(entry), "renderInvocations").tree,

    /** The credential/delegate tree, ASCII. */
    renderTree: (entry) => parse(addon.renderTree(entry), "renderTree").tree,
  };
}

module.exports = {
  load,
  platformKey,
  findAddon,
  findLibrary,
  nativeLibraryName,
  ...errors,
};
