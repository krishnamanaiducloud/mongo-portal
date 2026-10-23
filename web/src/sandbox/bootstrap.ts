// Sandbox page bootstrap (shell-sandbox.html).
//
// The page has an opaque origin and no network access. It starts the mongosh
// runtime in a dedicated worker so that runaway scripts (e.g. infinite loops)
// cannot block the portal page; the portal interrupts them by removing this
// frame, which terminates the worker. The parent's MessagePort is handed to
// the worker, so all further messages bypass this page.
import { INIT, READY, type InitMessage } from './protocol';

let started = false;

window.addEventListener('message', (ev: MessageEvent<InitMessage>) => {
  if (started || ev.source !== window.parent || ev.data?.type !== INIT || !ev.ports?.[0]) return;
  started = true;
  // A blob worker shares this document's opaque origin and CSP (no network,
  // no storage); it loads the runtime from the portal's static assets.
  const runtimeUrl = new URL('/shell-sandbox/worker.js', window.location.href).href;
  const blob = new Blob([`importScripts(${JSON.stringify(runtimeUrl)});`], { type: 'text/javascript' });
  const worker = new Worker(URL.createObjectURL(blob), { name: 'mongosh' });
  const init: InitMessage = { type: INIT, initialDb: String(ev.data.initialDb), uri: String(ev.data.uri) };
  worker.postMessage(init, [ev.ports[0]]);
});

window.parent.postMessage({ type: READY }, '*');
