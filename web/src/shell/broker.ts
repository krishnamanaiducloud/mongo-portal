// Broker between the portal page and the mongosh sandbox iframe.
//
// The sandbox is untrusted: it runs arbitrary user JavaScript. It can only
// talk to this broker through a MessagePort. The broker forwards allowlisted
// operations to the portal API, asks the user to confirm destructive ones,
// and limits concurrency. The server enforces every rule again.
import { api, ApiError, errorMessage } from '../api/client';
import type { DisplayError, DisplayValue } from '../sandbox/display';
import { INIT, READY, type FromSandbox, type ToSandbox } from '../sandbox/protocol';

/** Operations the sandbox may request (mirrors the server's shell API). */
export const READ_OPS = new Set([
  'connectionInfo', 'listDatabases', 'listCollections', 'getIndexes', 'find', 'aggregate', 'getMore',
  'killCursor', 'countDocuments', 'estimatedDocumentCount', 'distinct', 'explain', 'runCommand',
]);
export const WRITE_OPS = new Set([
  'insertOne', 'insertMany', 'updateOne', 'updateMany', 'replaceOne', 'deleteOne', 'deleteMany',
  'findOneAndDelete', 'findOneAndReplace', 'findOneAndUpdate', 'bulkWrite', 'createIndexes',
  'dropIndexes', 'createCollection', 'dropCollection', 'dropDatabase', 'renameCollection',
]);
/** Always confirmed, with the target name typed by the user. */
export const DROP_OPS = new Set(['dropCollection', 'dropDatabase', 'renameCollection']);
/** Confirmed; the user may allow them for the rest of this shell session. */
export const BULK_OPS = new Set(['updateMany', 'deleteMany', 'bulkWrite', 'dropIndexes']);
export const DESTRUCTIVE_COMMANDS = new Set(['dropIndexes', 'renameCollection', 'killOp']);

export interface ConfirmRequest {
  op: string;
  title: string;
  summary: string;
  /** Text the user must type, for drops. */
  typeToConfirm?: string;
  /** Whether "don't ask again in this shell session" may be offered. */
  allowRemember: boolean;
}

export interface ConfirmDecision {
  confirmed: boolean;
  remember?: boolean;
}

export interface EvalOutcome {
  ok: boolean;
  value?: DisplayValue;
  error?: DisplayError;
  prompt: string;
}

export interface BrokerHandlers {
  confirm: (req: ConfirmRequest) => Promise<ConfirmDecision>;
  onPrint: (values: DisplayValue[]) => void;
  onClear: () => void;
  onExit: () => void;
  canWrite: boolean;
}

type ApiCall = (op: string, args: string, confirm?: string) => Promise<string>;

const defaultApiCall: ApiCall = async (op, args, confirm) => {
  const r = await api<{ result: string }>('/shell', {
    method: 'POST',
    body: { op, args },
    headers: confirm ? { 'X-Confirm': confirm } : undefined,
  });
  return r.result;
};

function describe(op: string, a: Record<string, unknown>): string {
  const ns = [a.db, a.coll ?? a.from].filter(Boolean).join('.');
  const filter = a.filter !== undefined ? ` matching ${JSON.stringify(a.filter).slice(0, 300)}` : '';
  switch (op) {
    case 'deleteMany':
      return `Delete all documents in ${ns}${filter}.`;
    case 'updateMany':
      return `Update all documents in ${ns}${filter}.`;
    case 'bulkWrite':
      return `Run ${Array.isArray(a.operations) ? a.operations.length : 'several'} bulk write operations on ${ns}.`;
    case 'dropIndexes':
      return `Drop index ${JSON.stringify(a.index)} on ${ns}.`;
    case 'dropCollection':
      return `Permanently drop the collection ${ns} with all its documents and indexes.`;
    case 'dropDatabase':
      return `Permanently drop the database ${String(a.db)} and every collection in it.`;
    case 'renameCollection':
      return `Rename ${ns} to ${String(a.db)}.${String(a.to)}${a.dropTarget ? ', dropping the existing target collection' : ''}.`;
    case 'runCommand':
      return `Run the administrative command ${JSON.stringify(a.command).slice(0, 300)} on ${String(a.db)}.`;
  }
  return `${op} on ${ns}`;
}

/**
 * Decides whether an operation may be forwarded and with which confirmation.
 * Exported for unit tests.
 */
export async function authorizeOp(
  op: string,
  argsJson: string,
  canWrite: boolean,
  remembered: Set<string>,
  confirm: BrokerHandlers['confirm'],
): Promise<{ ok: true; confirmHeader?: string } | { ok: false; error: DisplayError }> {
  if (!READ_OPS.has(op) && !WRITE_OPS.has(op)) {
    return { ok: false, error: { name: 'MongoshUnimplementedError', message: `${op} is not supported in the portal shell` } };
  }
  if (WRITE_OPS.has(op) && !canWrite) {
    return { ok: false, error: { name: 'PortalPolicyError', message: `Your portal role is read-only; ${op} is not permitted` } };
  }
  let args: Record<string, unknown>;
  try {
    args = JSON.parse(argsJson) as Record<string, unknown>;
  } catch {
    return { ok: false, error: { name: 'PortalPolicyError', message: 'Malformed operation arguments' } };
  }
  let confirmOp: string | undefined;
  let typeToConfirm: string | undefined;
  if (DROP_OPS.has(op)) {
    confirmOp = op;
    typeToConfirm = op === 'dropDatabase' ? String(args.db) : String(args.coll ?? args.from ?? '');
  } else if (BULK_OPS.has(op)) {
    confirmOp = op;
  } else if (op === 'runCommand') {
    const cmd = args.command as Record<string, unknown> | undefined;
    const name = cmd ? Object.keys(cmd)[0] : '';
    if (name && DESTRUCTIVE_COMMANDS.has(name)) confirmOp = 'runCommand';
  }
  if (!confirmOp) return { ok: true };
  const rememberKey = op === 'runCommand' ? `runCommand:${Object.keys((args.command as object) ?? {})[0]}` : op;
  if (!DROP_OPS.has(op) && remembered.has(rememberKey)) return { ok: true, confirmHeader: confirmOp };
  const decision = await confirm({
    op,
    title: `Confirm ${op}`,
    summary: describe(op, args),
    typeToConfirm,
    allowRemember: !DROP_OPS.has(op),
  });
  if (!decision.confirmed) {
    return { ok: false, error: { name: 'PortalPolicyError', message: `${op} was cancelled` } };
  }
  if (decision.remember) remembered.add(rememberKey);
  return { ok: true, confirmHeader: confirmOp };
}

const POLICY_CODES = new Set(['operation_not_permitted', 'portal_role_forbidden', 'confirmation_required', 'csrf_failed', 'shell_disabled']);

export function apiErrorToDisplay(e: ApiError): DisplayError {
  if (POLICY_CODES.has(e.code)) return { name: 'PortalPolicyError', message: e.message };
  if (e.mongoCode) return { name: 'MongoServerError', message: e.message, code: e.mongoCode, codeName: e.codeName };
  if (e.code === 'invalid_query' || e.code === 'invalid_arguments') return { name: 'MongoshInvalidInputError', message: e.message };
  return { name: 'MongoshError', message: e.message };
}

export class ShellBroker {
  private iframe: HTMLIFrameElement | null = null;
  private port: MessagePort | null = null;
  private seq = 0;
  private inflight = 0;
  private readonly queue: (() => void)[] = [];
  private readonly evals = new Map<number, (o: EvalOutcome) => void>();
  private readonly completions = new Map<number, (l: string[]) => void>();
  private readonly remembered = new Set<string>();
  private readonly handlers: BrokerHandlers;
  private readonly apiCall: ApiCall;
  private windowListener: ((ev: MessageEvent) => void) | null = null;
  private destroyed = false;

  constructor(handlers: BrokerHandlers, apiCall: ApiCall = defaultApiCall) {
    this.handlers = handlers;
    this.apiCall = apiCall;
  }

  /** Creates the sandbox iframe and resolves when mongosh has started. */
  start(container: HTMLElement, initialDb: string, uri: string): Promise<{ prompt: string; version: string }> {
    return new Promise((resolve, reject) => {
      const frame = document.createElement('iframe');
      frame.setAttribute('sandbox', 'allow-scripts');
      frame.setAttribute('title', 'mongosh sandbox');
      frame.setAttribute('aria-hidden', 'true');
      frame.setAttribute('tabindex', '-1');
      frame.setAttribute('referrerpolicy', 'no-referrer');
      frame.style.display = 'none';
      frame.src = '/shell-sandbox.html';
      this.iframe = frame;

      const timer = window.setTimeout(() => reject(new Error('The shell did not start in time')), 60_000);
      this.windowListener = (ev: MessageEvent) => {
        // Handshake only: accept READY solely from our iframe, then talk over a private port.
        if (this.port || ev.source !== frame.contentWindow || (ev.data as { type?: string })?.type !== READY) return;
        const channel = new MessageChannel();
        this.port = channel.port1;
        this.port.onmessage = (e: MessageEvent<FromSandbox>) => {
          const m = e.data;
          if (m?.type === 'started') {
            window.clearTimeout(timer);
            resolve({ prompt: m.prompt, version: m.version });
            return;
          }
          this.onMessage(m);
        };
        // The sandbox has an opaque origin, so "*" is the only possible target;
        // the message carries no secrets, only the port and the initial database.
        frame.contentWindow?.postMessage({ type: INIT, initialDb, uri }, '*', [channel.port2]);
      };
      window.addEventListener('message', this.windowListener);
      container.appendChild(frame);
    });
  }

  destroy() {
    this.destroyed = true;
    if (this.windowListener) window.removeEventListener('message', this.windowListener);
    this.port?.close();
    this.iframe?.remove();
    this.iframe = null;
    this.port = null;
    for (const resolve of this.evals.values()) {
      resolve({ ok: false, error: { name: 'Interrupted', message: 'The shell was reset' }, prompt: '> ' });
    }
    this.evals.clear();
    for (const resolve of this.completions.values()) resolve([]);
    this.completions.clear();
  }

  evaluate(code: string): Promise<EvalOutcome> {
    const id = ++this.seq;
    return new Promise((resolve) => {
      this.evals.set(id, resolve);
      this.post({ type: 'eval', id, code });
    });
  }

  complete(code: string): Promise<string[]> {
    const id = ++this.seq;
    return new Promise((resolve) => {
      this.completions.set(id, resolve);
      this.post({ type: 'complete', id, code });
      // The first completion initialises mongosh's TypeScript-based
      // autocompleter, which can take several seconds.
      window.setTimeout(() => {
        if (this.completions.delete(id)) resolve([]);
      }, 30_000);
    });
  }

  private post(m: ToSandbox) {
    this.port?.postMessage(m);
  }

  private onMessage(m: FromSandbox) {
    if (!m || typeof m !== 'object' || this.destroyed) return;
    switch (m.type) {
      case 'result': {
        const r = this.evals.get(m.id);
        if (!r) return;
        this.evals.delete(m.id);
        r(m.ok ? { ok: true, value: m.value, prompt: m.prompt } : { ok: false, error: m.error, prompt: m.prompt });
        return;
      }
      case 'completions': {
        const r = this.completions.get(m.id);
        if (!r) return;
        this.completions.delete(m.id);
        r(Array.isArray(m.list) ? m.list.map(String).slice(0, 50) : []);
        return;
      }
      case 'print':
        if (Array.isArray(m.values)) this.handlers.onPrint(m.values.slice(0, 1000));
        return;
      case 'clear':
        this.handlers.onClear();
        return;
      case 'exit':
        this.handlers.onExit();
        return;
      case 'op':
        if (typeof m.id === 'number' && typeof m.op === 'string' && typeof m.args === 'string') {
          this.enqueue(() => this.runOp(m.id, m.op, m.args));
        }
    }
  }

  /** At most four operations in flight; the rest wait. */
  private enqueue(task: () => Promise<void>) {
    const run = () => {
      this.inflight++;
      void task().finally(() => {
        this.inflight--;
        this.queue.shift()?.();
      });
    };
    if (this.inflight < 4) run();
    else this.queue.push(run);
  }

  private async runOp(id: number, op: string, args: string) {
    const auth = await authorizeOp(op, args, this.handlers.canWrite, this.remembered, this.handlers.confirm);
    if (!auth.ok) {
      this.post({ type: 'reply', id, ok: false, error: auth.error });
      return;
    }
    try {
      const result = await this.apiCall(op, args, auth.confirmHeader);
      this.post({ type: 'reply', id, ok: true, result });
    } catch (e) {
      const err: DisplayError = e instanceof ApiError ? apiErrorToDisplay(e) : { name: 'MongoshError', message: errorMessage(e) };
      this.post({ type: 'reply', id, ok: false, error: err });
    }
  }
}
