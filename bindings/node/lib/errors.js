"use strict";

/**
 * The typed errors the Node binding raises.
 *
 * The C ABI reports the Go sentinel a failure wraps as `kind`; this maps each
 * kind to its own class so a caller can `try { … } catch (e) { if (e instanceof
 * MissingSigner) … }` rather than string-matching a message. `kind` stays on
 * every error too, for a switch or a log line.
 *
 * The distinction is the point: the Go library refuses rather than guessing —
 * "no signer for this address" and "unsupported credentials arm" are different
 * facts a caller handles differently, and flattening them into one Error would
 * throw that away across the language boundary.
 */

/** The base class every binding error extends. */
class SoroauthError extends Error {
  /**
   * @param {string} message the library's message, which already names the
   *   operation and the rule it enforced.
   * @param {string} kind the ABI kind, or "ERROR".
   */
  constructor(message, kind = "ERROR") {
    super(message);
    this.name = new.target.name;
    this.kind = kind;
  }
}

/** A signer's own signature did not verify. */
class SignatureMismatch extends SoroauthError {
  constructor(message) {
    super(message, "SIGNATURE_MISMATCH");
  }
}

/** The entry uses SOROBAN_CREDENTIALS_SOURCE_ACCOUNT, which has no payload. */
class SourceAccountCredentials extends SoroauthError {
  constructor(message) {
    super(message, "SOURCE_ACCOUNT_CREDENTIALS");
  }
}

/** The credentials arm is one this build does not implement. */
class UnsupportedCredentials extends SoroauthError {
  constructor(message) {
    super(message, "UNSUPPORTED_CREDENTIALS");
  }
}

/** No credential node matched the target address (fail-closed target rule). */
class NoMatchingCredentialNode extends SoroauthError {
  constructor(message) {
    super(message, "NO_MATCHING_CREDENTIAL_NODE");
  }
}

/** One address appears twice at the same delegate level (CAP-71-01). */
class DuplicateDelegate extends SoroauthError {
  constructor(message) {
    super(message, "DUPLICATE_DELEGATE");
  }
}

/** An address-arm entry has no signer for its address. */
class MissingSigner extends SoroauthError {
  constructor(message) {
    super(message, "MISSING_SIGNER");
  }
}

/** Signing would overwrite or invalidate an existing signature. */
class AlreadySigned extends SoroauthError {
  constructor(message) {
    super(message, "ALREADY_SIGNED");
  }
}

/** The expiration ledger is unusable (zero, overflow, or a mismatch). */
class InvalidExpiration extends SoroauthError {
  constructor(message) {
    super(message, "INVALID_EXPIRATION");
  }
}

/** More signing keys than the host accepts for a classic account. */
class TooManySignatures extends SoroauthError {
  constructor(message) {
    super(message, "TOO_MANY_SIGNATURES");
  }
}

/** Untrusted input exceeded a decode limit. */
class DecodeLimit extends SoroauthError {
  constructor(message) {
    super(message, "DECODE_LIMIT");
  }
}

/** Maps an ABI kind to its class. Unknown kinds fall back to SoroauthError. */
const BY_KIND = {
  SOURCE_ACCOUNT_CREDENTIALS: SourceAccountCredentials,
  UNSUPPORTED_CREDENTIALS: UnsupportedCredentials,
  NO_MATCHING_CREDENTIAL_NODE: NoMatchingCredentialNode,
  DUPLICATE_DELEGATE: DuplicateDelegate,
  SIGNATURE_MISMATCH: SignatureMismatch,
  MISSING_SIGNER: MissingSigner,
  ALREADY_SIGNED: AlreadySigned,
  INVALID_EXPIRATION: InvalidExpiration,
  TOO_MANY_SIGNATURES: TooManySignatures,
  DECODE_LIMIT: DecodeLimit,
};

/**
 * from builds the right error from a failed ABI envelope. It never returns a
 * success: an envelope that is missing or not `ok` is an error even when it
 * carries no message, so a malformed reply cannot pass as a result.
 */
function from(envelope) {
  const kind = typeof envelope?.kind === "string" ? envelope.kind : "ERROR";
  const message =
    typeof envelope?.error === "string" && envelope.error !== ""
      ? envelope.error
      : "soroauth: the native library reported a failure with no message";
  const Class = BY_KIND[kind] ?? SoroauthError;
  return new Class(message);
}

module.exports = {
  SoroauthError,
  SignatureMismatch,
  SourceAccountCredentials,
  UnsupportedCredentials,
  NoMatchingCredentialNode,
  DuplicateDelegate,
  MissingSigner,
  AlreadySigned,
  InvalidExpiration,
  TooManySignatures,
  DecodeLimit,
  from,
  BY_KIND,
};
