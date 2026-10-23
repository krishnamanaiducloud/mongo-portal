// The mongosh runtime, running in a dedicated worker started by the sandbox
// page (see bootstrap.ts). The worker shares the sandbox's opaque origin and
// CSP: it cannot make network requests or read cookies or storage. User
// JavaScript is evaluated here by the real mongosh runtime; every database
// operation is sent to the portal page broker over a MessagePort.
import './shims/globals';
import * as bson from 'bson';
import { OpenContextRuntime } from '@mongosh/browser-runtime-core';
import { PortalServiceProvider } from './provider';
import { toDisplay, toDisplayError, type DisplayError } from './display';
import { INIT, type FromSandbox, type InitMessage, type ToSandbox } from './protocol';

let port: MessagePort | null = null;
let runtime: OpenContextRuntime | null = null;
let seq = 0;
const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: unknown) => void }>();

function send(msg: FromSandbox) {
  port?.postMessage(msg);
}

class RemoteError extends Error {
  code?: number;
  codeName?: string;
  constructor(e: DisplayError) {
    super(e.message);
    this.name = e.name;
    this.code = e.code;
    this.codeName = e.codeName;
  }
}

function rpc(op: string, args: Record<string, unknown>): Promise<unknown> {
  const id = ++seq;
  const payload = bson.EJSON.stringify(args, { relaxed: false });
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    send({ type: 'op', id, op, args: payload });
  });
}

async function prompt(): Promise<string> {
  try {
    return (await runtime?.getShellPrompt()) ?? '> ';
  } catch {
    return '> ';
  }
}

async function onMessage(ev: MessageEvent<ToSandbox>) {
  const m = ev.data;
  if (!m || typeof m !== 'object' || !runtime) return;
  switch (m.type) {
    case 'reply': {
      const p = pending.get(m.id);
      if (!p) return;
      pending.delete(m.id);
      if (m.ok) {
        try {
          p.resolve(bson.EJSON.parse(m.result, { relaxed: false }));
        } catch (e) {
          p.reject(e);
        }
      } else {
        p.reject(new RemoteError(m.error));
      }
      return;
    }
    case 'eval': {
      try {
        const r = await runtime.evaluate(String(m.code));
        send({ type: 'result', id: m.id, ok: true, value: toDisplay(r), prompt: await prompt() });
      } catch (e) {
        send({ type: 'result', id: m.id, ok: false, error: toDisplayError(e), prompt: await prompt() });
      }
      return;
    }
    case 'complete': {
      try {
        const list = await runtime.getCompletions(String(m.code));
        send({ type: 'completions', id: m.id, list: list.map((c) => c.completion).slice(0, 50) });
      } catch (e) {
        console.warn('mongosh autocompletion failed:', e instanceof Error ? e.message : e);
        send({ type: 'completions', id: m.id, list: [] });
      }
    }
  }
}

function start(init: InitMessage) {
  const provider = new PortalServiceProvider(rpc, { initialDb: init.initialDb, uri: init.uri });
  runtime = new OpenContextRuntime(provider as never, {
    // Global (indirect) eval in this sandboxed realm.
    sloppyEval: (code: string) => (0, globalThis.eval)(code),
    getContextObject: () => globalThis,
  });
  runtime.setEvaluationListener({
    onPrint: (values) => send({ type: 'print', values: values.map(toDisplay) }),
    onPrompt: async () => '',
    onClearCommand: () => send({ type: 'clear' }),
    onExit: async () => {
      send({ type: 'exit' });
      return new Promise<never>(() => undefined);
    },
  });
  void prompt().then(async (p) => {
    const version = await runtime!.evaluate('version()').then((v) => String(v.printable ?? ''), () => '');
    send({ type: 'started', prompt: p, version });
    // Warm up the autocompleter in the background so the first Tab is fast.
    void runtime!.getCompletions('db.').catch(() => undefined);
  });
}

self.addEventListener('message', (ev: MessageEvent<InitMessage>) => {
  // Accept exactly one init message (from the bootstrap page) carrying the broker port.
  if (port || ev.data?.type !== INIT || !ev.ports?.[0]) return;
  port = ev.ports[0];
  port.onmessage = (e) => void onMessage(e);
  start(ev.data);
});
