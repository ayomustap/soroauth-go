/**
 * The popup: paste an entry, see its structure.
 *
 * This is the same `buildReport`/`renderReport` the in-page gate uses, over the
 * same wasm core, so the two surfaces cannot disagree about what an entry says.
 * The popup does not ask for a decision — the gate does that, in the page, next
 * to the button that would sign.
 */

import { loadCore } from "./core.js";
import { buildReport } from "./report.js";
import { renderReport } from "./overlay.js";

const form = document.getElementById("explain-form");
const entryField = document.getElementById("entry");
const validUntilField = document.getElementById("valid-until");
const status = document.getElementById("status");
const reportHost = document.getElementById("report");

/** setStatus writes a message, or clears it when text is empty. */
function setStatus(text, isError = false) {
  status.textContent = text;
  status.hidden = text === "";
  status.classList.toggle("soroauth-popup__status--error", isError);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  reportHost.replaceChildren();
  setStatus("Loading the signing core…");
  try {
    const core = await loadCore();
    const entry = entryField.value.trim();
    const validUntil = validUntilField.value === "" ? undefined : Number(validUntilField.value);
    const report = buildReport({ core, entryXdr: entry, validUntilLedger: validUntil });
    reportHost.append(renderReport(report, document));
    setStatus("");
  } catch (error) {
    // The core's message already names the operation and the rule it enforced.
    setStatus(String(error?.message ?? error), true);
  }
});
