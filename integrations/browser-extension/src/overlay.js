/**
 * Render a report and require an explicit decision.
 *
 * The rendering is deliberately plain DOM with no framework, so the reference
 * extension is one file you can read. `doc` is injected so the same code runs
 * in a page and is exercised by `test/report.test.mjs` against a minimal
 * document stub, rather than only in a browser nobody automated.
 *
 * The confirmation rule is the point: nothing approves a request except a click
 * on the approve button. Escape, the backdrop, or closing the dialog all
 * resolve to refusal, and a caller that gets no decision must treat that as
 * refusal too.
 */

import { ANALYZER_LIMITS } from "./report.js";

/** The class prefix every element this module creates carries. */
const PREFIX = "soroauth-explain";

function element(doc, tag, className) {
  const node = doc.createElement(tag);
  if (className) node.className = className;
  return node;
}

function definitionRow(doc, term, value) {
  const dt = element(doc, "dt");
  dt.textContent = term;
  const dd = element(doc, "dd");
  dd.textContent = value;
  return [dt, dd];
}

function rootCallLabel(report) {
  if (!report.rootContract && !report.rootFunction) {
    return "not a contract call (a create-contract authorization)";
  }
  return `${report.rootFunction} on ${report.rootContract}`;
}

function section(doc, title, body) {
  const wrapper = element(doc, "section", `${PREFIX}__section`);
  const heading = element(doc, "h2", `${PREFIX}__section-title`);
  heading.textContent = title;
  wrapper.append(heading, body);
  return wrapper;
}

function pre(doc, text) {
  const block = element(doc, "pre", `${PREFIX}__tree`);
  block.textContent = text;
  return block;
}

function findingsBody(doc, report) {
  const list = element(doc, "ul", `${PREFIX}__findings`);
  if (!report.findings || report.findings.length === 0) {
    const item = element(doc, "li", `${PREFIX}__finding ${PREFIX}__finding--none`);
    item.textContent =
      "No findings. The heuristics below matched nothing; that is not a clean bill of health.";
    list.append(item);
    return list;
  }
  for (const finding of report.findings) {
    const item = element(doc, "li", `${PREFIX}__finding ${PREFIX}__finding--${finding.severity}`);
    const title = element(doc, "strong", `${PREFIX}__finding-title`);
    title.textContent = `[${finding.severity}] ${finding.title} (${finding.code})`;
    const description = element(doc, "p", `${PREFIX}__finding-description`);
    description.textContent = finding.description;
    const rationale = element(doc, "p", `${PREFIX}__finding-rationale`);
    rationale.textContent = finding.rationale;
    item.append(title, description, rationale);
    list.append(item);
  }
  return list;
}

function limitsBody(doc) {
  const list = element(doc, "ul", `${PREFIX}__limits`);
  for (const limit of ANALYZER_LIMITS) {
    const item = element(doc, "li");
    item.textContent = limit;
    list.append(item);
  }
  return list;
}

/**
 * renderReport builds the panel for one report.
 *
 * Every number and tree in it came from the wasm core, and the disclaimer and
 * the analyzer's limits are part of the panel rather than optional extras: a
 * caller cannot render this report as a safety verdict without deleting the
 * text that says it is not one.
 */
export function renderReport(report, doc = document) {
  const root = element(doc, "div", `${PREFIX}__panel`);
  root.setAttribute("role", "dialog");
  root.setAttribute("aria-modal", "true");
  root.setAttribute("aria-label", "Soroban authorization request");

  const heading = element(doc, "h1", `${PREFIX}__title`);
  heading.textContent = "Review this authorization request";
  root.append(heading);

  const disclaimer = element(doc, "p", `${PREFIX}__disclaimer`);
  disclaimer.textContent = report.disclaimer;
  root.append(disclaimer);

  const summary = element(doc, "dl", `${PREFIX}__summary`);
  summary.append(...definitionRow(doc, "Credential arm", report.armLabel));
  if (report.address) summary.append(...definitionRow(doc, "Address", report.address));
  summary.append(
    ...definitionRow(doc, "Address-bound", report.addressBound ? "yes (CAP-71)" : "no"),
  );
  if (report.nonce !== null && report.nonce !== undefined) {
    summary.append(...definitionRow(doc, "Nonce", String(report.nonce)));
  }
  if (report.validUntilLedger !== null && report.validUntilLedger !== undefined) {
    summary.append(
      ...definitionRow(doc, "Valid until ledger", `${report.validUntilLedger} (inclusive)`),
    );
  }
  summary.append(
    ...definitionRow(doc, "Top-level signed", report.topLevelSigned ? "yes" : "no"),
  );
  summary.append(...definitionRow(doc, "Root call", rootCallLabel(report)));
  summary.append(
    ...definitionRow(doc, "Sub-invocations", String(report.subInvocations ?? 0)),
  );
  root.append(summary);

  if (report.credentialTree) {
    root.append(section(doc, "Credential and delegate tree", pre(doc, report.credentialTree)));
  }
  root.append(section(doc, "Invocation tree", pre(doc, report.invocationTree)));
  root.append(section(doc, "Risk findings", findingsBody(doc, report)));
  root.append(section(doc, "What the analyzer cannot see", limitsBody(doc)));

  return root;
}

/**
 * confirmReport renders `report` as a modal and resolves with the user's
 * decision: `true` only from the approve button, `false` from reject, Escape,
 * or a click on the backdrop.
 *
 * The promise always settles with a boolean; it never rejects, so a caller
 * cannot skip the check with a missing catch. A caller that receives no value
 * at all (the page navigated away, the dialog was removed) must treat it as
 * refusal — see `explain-gate.js` in the passkey example, which does.
 */
export function confirmReport({ report, doc = document, mount = doc.body }) {
  return new Promise((resolve) => {
    const backdrop = element(doc, "div", `${PREFIX}__backdrop`);
    const panel = renderReport(report, doc);

    const actions = element(doc, "div", `${PREFIX}__actions`);
    const reject = element(doc, "button", `${PREFIX}__reject`);
    reject.type = "button";
    reject.textContent = "Reject";
    const approve = element(doc, "button", `${PREFIX}__approve`);
    approve.type = "button";
    approve.textContent = "Approve and sign";
    actions.append(reject, approve);
    panel.append(actions);
    backdrop.append(panel);

    const onKeyDown = (event) => {
      if (event.key === "Escape") finish(false);
    };

    function finish(approved) {
      doc.removeEventListener("keydown", onKeyDown);
      backdrop.remove();
      resolve(approved);
    }

    reject.addEventListener("click", () => finish(false));
    approve.addEventListener("click", () => finish(true));
    backdrop.addEventListener("click", (event) => {
      // Only a click on the backdrop itself dismisses; a click inside the panel
      // must not count as a decision either way.
      if (event.target === backdrop) finish(false);
    });
    doc.addEventListener("keydown", onKeyDown);

    mount.append(backdrop);
  });
}
