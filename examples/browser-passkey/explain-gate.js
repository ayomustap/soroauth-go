/**
 * The gate the passkey demo calls before it signs.
 *
 * A browser user asked to sign an authorization entry otherwise sees base64.
 * The `soroauth` explanation extension (integrations/browser-extension) injects
 * `globalThis.soroauthExplain`; when it is present this hands it the unsigned
 * entry and waits for an explicit decision, so the user sees the credential arm,
 * the address, the nonce, the expiration, the delegate and invocation trees and
 * the risk analyzer's findings before the authenticator is asked to sign.
 *
 * The gate is optional on purpose: the demo has to keep working with no
 * extension installed. "No gate" means the request proceeds, which is the
 * status quo; a gate that is present but fails or declines means refusal, so an
 * error in the extension can never silently downgrade to signing anyway.
 *
 * This module imports nothing, so a Node check can exercise it without a
 * browser (see integrations/browser-extension/test/report.test.mjs).
 */

/**
 * requestExplanation returns whether the request may proceed.
 *
 * The result is `{ approved, gate }`, where `gate` is `"absent"` (no extension),
 * `"extension"` (the extension decided), or `"error"` (the extension threw).
 * `approved` is true only for `"absent"` or an explicit `true` from the
 * extension.
 */
export async function requestExplanation(detail) {
  const gate = globalThis.soroauthExplain;
  if (!gate || typeof gate.confirm !== "function") {
    return { approved: true, gate: "absent" };
  }

  let decision;
  try {
    decision = await gate.confirm(detail);
  } catch (cause) {
    return {
      approved: false,
      gate: "error",
      reason: String(cause?.message ?? cause),
    };
  }

  // Strictly true: anything else (undefined from a dismissed dialog, a truthy
  // non-boolean, a promise that resolved to nothing) is not an approval.
  return { approved: decision === true, gate: "extension" };
}
