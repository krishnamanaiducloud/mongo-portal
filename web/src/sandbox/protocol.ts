// Messages exchanged between the portal page (broker) and the sandbox.
import type { DisplayError, DisplayValue } from './display';

export const READY = 'portal-shell-ready';
export const INIT = 'portal-shell-init';

export interface InitMessage {
  type: typeof INIT;
  initialDb: string;
  uri: string;
}

/** Parent -> sandbox over the MessagePort. */
export type ToSandbox =
  | { type: 'eval'; id: number; code: string }
  | { type: 'complete'; id: number; code: string }
  | { type: 'reply'; id: number; ok: true; result: string }
  | { type: 'reply'; id: number; ok: false; error: DisplayError };

/** Sandbox -> parent over the MessagePort. */
export type FromSandbox =
  | { type: 'started'; prompt: string; version: string }
  | { type: 'result'; id: number; ok: true; value: DisplayValue; prompt: string }
  | { type: 'result'; id: number; ok: false; error: DisplayError; prompt: string }
  | { type: 'completions'; id: number; list: string[] }
  | { type: 'print'; values: DisplayValue[] }
  | { type: 'clear' }
  | { type: 'exit' }
  | { type: 'op'; id: number; op: string; args: string };
