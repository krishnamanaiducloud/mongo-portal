// Minimal Node.js globals expected by the mongosh packages. Imported first
// by the sandbox entry so it runs before any module that reads them.
import { Buffer } from 'buffer';

type ProcessShim = {
  env: Record<string, string>;
  version: string;
  versions: Record<string, string>;
  platform: string;
  argv: string[];
  cwd: () => string;
  nextTick: (fn: (...args: unknown[]) => void, ...args: unknown[]) => void;
  emitWarning: () => void;
};

const g = globalThis as unknown as { process?: ProcessShim; Buffer?: typeof Buffer; global?: unknown };

g.process ??= {
  // USE_NEW_AUTOCOMPLETE=0 selects mongosh's classic completer; the newer
  // TypeScript-based one needs Node file system access.
  env: { NODE_ENV: 'production', USE_NEW_AUTOCOMPLETE: '0' },
  version: '',
  versions: {},
  platform: 'browser',
  argv: [],
  cwd: () => '/',
  nextTick: (fn, ...args) => queueMicrotask(() => fn(...args)),
  emitWarning: () => undefined,
};
g.Buffer ??= Buffer;
g.global ??= globalThis;
