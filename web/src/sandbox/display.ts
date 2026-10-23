// Converts mongosh evaluation results into a serializable display model that
// the parent page renders. Values are canonical Extended JSON so BSON types
// survive the postMessage boundary.
import * as bson from 'bson';

export interface DisplayValue {
  /** mongosh result type, e.g. "Cursor", "Help", "Document"; null for plain values. */
  type: string | null;
  /** Canonical Extended JSON of the printable value, or a string. */
  value: unknown;
  /** True when the value could only be rendered as text. */
  text?: boolean;
}

export function toDisplay(result: { type?: string | null; printable: unknown }): DisplayValue {
  const type = result.type ?? null;
  const p = result.printable;
  if (p === undefined) return { type, value: 'undefined', text: true };
  if (p === null || typeof p === 'string' || typeof p === 'number' || typeof p === 'boolean') {
    return { type, value: p };
  }
  if (typeof p === 'bigint') return { type, value: `${p.toString()}n`, text: true };
  if (typeof p === 'function') return { type, value: `[Function${p.name ? `: ${p.name}` : ''}]`, text: true };
  try {
    return { type, value: bson.EJSON.serialize(p, { relaxed: false }) };
  } catch {
    try {
      return { type, value: String(p), text: true };
    } catch {
      return { type, value: '[unprintable value]', text: true };
    }
  }
}

export interface DisplayError {
  name: string;
  message: string;
  code?: number;
  codeName?: string;
}

export function toDisplayError(e: unknown): DisplayError {
  if (e && typeof e === 'object') {
    const err = e as { name?: string; message?: string; code?: unknown; codeName?: unknown };
    return {
      name: String(err.name ?? 'Error'),
      message: String(err.message ?? e),
      code: typeof err.code === 'number' ? err.code : undefined,
      codeName: typeof err.codeName === 'string' ? err.codeName : undefined,
    };
  }
  return { name: 'Error', message: String(e) };
}
