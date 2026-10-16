/**
 * Inject the explanation gate into the page's world.
 *
 * A content script runs in an isolated world, so it cannot define a global the
 * page's own code can see. Injecting `injected.js` as a module script does that
 * in the page's world, and a module script can import the web-accessible
 * extension resources (`report.js`, the vendored wrapper, the wasm) without
 * another layer of messaging.
 *
 * The script tag is appended to `document.documentElement` when it exists and
 * otherwise on DOMContentLoaded, because a content script with
 * `run_at: document_start` can run before the document element is there.
 */
(function install() {
  function inject() {
    const target = document.head ?? document.documentElement;
    if (!target) return false;
    const script = document.createElement("script");
    script.type = "module";
    script.src = chrome.runtime.getURL("src/injected.js");
    script.dataset.soroauthExplain = "1";
    target.append(script);
    return true;
  }

  if (inject()) return;
  document.addEventListener("DOMContentLoaded", inject, { once: true });
})();
