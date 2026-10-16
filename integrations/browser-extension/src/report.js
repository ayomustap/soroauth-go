/**
 * Build the structural report a signing request is shown with.
 *
 * Everything here comes from the wasm signing core — `inspect`, `analyze`,
 * `renderTree` and `renderInvocations` are the same `soroauth.Inspect`,
 * `soroauth.Analyze` and tree renderers the library, the CLI and the other
 * bindings call. This module assembles their output; it reimplements none of
 * it, which is the whole point: a second implementation of "what does this
 * entry authorize" is a second thing that can be wrong.
 *
 * What this is not: an explainer. It reports that the entry authorizes
 * `transfer` on some contract with three arguments, not what transferring
 * means, whether the arguments are reasonable, or whether the contract is one
 * you trust. That is `soroauth-explain`'s problem, and the disclaimer and the
 * analyzer's limits travel with every report so a UI cannot present the
 * structure as a verdict.
 */

/** The boundary statement every rendered report carries. */
export const DISCLAIMER =
  "This reports the entry's structure only. It does not interpret what the contract call will do, decode its arguments, or say whether the call is safe.";

/**
 * The analyzer's documented limits, mirroring docs/analyzer-heuristics.md.
 * They are shown next to the findings, not behind a toggle, so a UI cannot
 * imply more certainty than the analyzer has.
 */
export const ANALYZER_LIMITS = [
  "The analyzer reads structure only: it does not decode contract arguments or evaluate contract behavior.",
  "A finding is not a verdict. A report with no findings means these heuristics matched nothing, not that the entry is safe.",
  "It cannot see a contract's Wasm, an account's real signing policy, or the network's live-until ceiling.",
];

/** Human labels for the credential arms, from the core's stable type strings. */
const ARM_LABELS = {
  source_account: "Source account (the transaction envelope authenticates it)",
  address: "Address credentials (legacy, CAP-46-11)",
  address_v2: "Address credentials V2 (CAP-71-01, address-bound)",
  address_with_delegates: "Address credentials with delegates (CAP-71-01)",
};

/** describeArm maps a credential type to the label a user reads. */
export function describeArm(credentialType) {
  return ARM_LABELS[credentialType] ?? `Unrecognised credential arm: ${credentialType}`;
}

const SEVERITY_ORDER = { info: 0, warning: 1, critical: 2 };

/**
 * highestSeverity returns the most severe finding's severity, or null when
 * there are none. It exists so a UI can rank the request without re-deriving
 * the ordering.
 */
export function highestSeverity(findings) {
  let highest = null;
  for (const finding of findings ?? []) {
    if (highest === null || (SEVERITY_ORDER[finding.severity] ?? 0) > (SEVERITY_ORDER[highest] ?? 0)) {
      highest = finding.severity;
    }
  }
  return highest;
}

/**
 * buildReport turns an unsigned entry into the report object.
 *
 * `core` is the `@soroauth/wasm` typing surface (the vendored wrapper in the
 * browser, the same package in tests). `entryXdr` is base64 XDR. A source
 * account entry has no address and no preimage, so it is reported as such and
 * no tree is drawn rather than inventing one.
 *
 * Throws when the core throws (a malformed entry, an unreadable invocation
 * arm), so a caller never renders a partial report as if it were complete.
 */
export function buildReport({ core, entryXdr, validUntilLedger, currentLedger }) {
  if (typeof entryXdr !== "string" || entryXdr.trim() === "") {
    throw new Error("no entry to explain: supply the base64 XDR of an authorization entry");
  }

  const info = core.inspect(entryXdr);

  if (info.credential_type === "source_account") {
    return {
      credentialType: info.credential_type,
      armLabel: describeArm(info.credential_type),
      addressBound: false,
      address: null,
      nonce: null,
      validUntilLedger: null,
      topLevelSigned: false,
      delegates: [],
      rootContract: info.root_contract ?? null,
      rootFunction: info.root_function ?? null,
      subInvocations: info.sub_invocations,
      credentialTree: null,
      invocationTree: core.renderInvocations(entryXdr),
      findings: [],
      highestSeverity: null,
      disclaimer: DISCLAIMER,
      analyzerLimits: ANALYZER_LIMITS,
    };
  }

  const findings = core.analyze(entryXdr, currentLedger ?? 0);

  return {
    credentialType: info.credential_type,
    armLabel: describeArm(info.credential_type),
    addressBound: info.address_bound,
    address: info.address ?? null,
    // The core's JSON omits nonce and expiration when they are zero, so the
    // caller's own validUntil is the fallback for the field the request was
    // made with.
    nonce: info.nonce ?? 0,
    validUntilLedger: info.valid_until_ledger ?? validUntilLedger ?? null,
    topLevelSigned: info.top_level_signed,
    delegates: info.delegates ?? [],
    rootContract: info.root_contract ?? null,
    rootFunction: info.root_function ?? null,
    subInvocations: info.sub_invocations,
    credentialTree: core.renderTree(entryXdr, "ascii"),
    invocationTree: core.renderInvocations(entryXdr),
    findings,
    highestSeverity: highestSeverity(findings),
    disclaimer: DISCLAIMER,
    analyzerLimits: ANALYZER_LIMITS,
  };
}
