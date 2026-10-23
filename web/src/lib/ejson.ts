// Helpers for MongoDB Extended JSON v2 (canonical and relaxed).

export type BsonKind =
  | 'objectId'
  | 'date'
  | 'decimal'
  | 'long'
  | 'int'
  | 'double'
  | 'binary'
  | 'uuid'
  | 'timestamp'
  | 'regex'
  | 'minKey'
  | 'maxKey'
  | 'symbol'
  | 'code'
  | 'dbPointer'
  | 'undefined';

export interface BsonValue {
  kind: BsonKind;
  display: string;
  detail?: string;
}

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

function only(o: Obj, ...k: string[]): boolean {
  const keys = Object.keys(o);
  return keys.length === k.length && k.every((x) => keys.includes(x));
}

export function base64Length(b64: string): number {
  const clean = b64.replace(/=+$/, '');
  return Math.floor((clean.length * 3) / 4);
}

function base64ToHex(b64: string): string {
  try {
    const bin = atob(b64);
    let out = '';
    for (let i = 0; i < bin.length; i++) out += bin.charCodeAt(i).toString(16).padStart(2, '0');
    return out;
  } catch {
    return '';
  }
}

function formatUuid(hex: string): string {
  if (hex.length !== 32) return hex;
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function dateDisplay(v: unknown): string | null {
  let ms: number | null = null;
  if (typeof v === 'string') {
    const t = Date.parse(v);
    if (!Number.isNaN(t)) return `ISODate("${new Date(t).toISOString()}")`;
    return `ISODate("${v}")`;
  }
  if (isObj(v) && typeof v.$numberLong === 'string') ms = Number(v.$numberLong);
  if (typeof v === 'number') ms = v;
  if (ms === null || !Number.isFinite(ms)) return null;
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? `Date(${ms})` : `ISODate("${d.toISOString()}")`;
}

/** Detects an Extended JSON type wrapper and returns a shell-style display. */
export function detectBson(v: unknown): BsonValue | null {
  if (!isObj(v)) return null;
  if (only(v, '$oid') && typeof v.$oid === 'string') return { kind: 'objectId', display: `ObjectId("${v.$oid}")` };
  if (only(v, '$date')) {
    const d = dateDisplay(v.$date);
    if (d) return { kind: 'date', display: d };
  }
  if (only(v, '$numberDecimal') && typeof v.$numberDecimal === 'string')
    return { kind: 'decimal', display: `NumberDecimal("${v.$numberDecimal}")` };
  if (only(v, '$numberLong') && typeof v.$numberLong === 'string') return { kind: 'long', display: `NumberLong(${v.$numberLong})` };
  if (only(v, '$numberInt') && typeof v.$numberInt === 'string') return { kind: 'int', display: v.$numberInt };
  if (only(v, '$numberDouble') && typeof v.$numberDouble === 'string') {
    const s = v.$numberDouble;
    return { kind: 'double', display: /^-?\d+$/.test(s) ? `${s}.0` : s };
  }
  if (only(v, '$binary') && isObj(v.$binary)) {
    const b64 = String(v.$binary.base64 ?? '');
    const sub = String(v.$binary.subType ?? '00');
    if (sub === '04' || sub === '03') {
      const hex = base64ToHex(b64);
      if (hex.length === 32) return { kind: 'uuid', display: `UUID("${formatUuid(hex)}")`, detail: `subtype ${sub}` };
    }
    const len = base64Length(b64);
    const preview = b64.length > 24 ? `${b64.slice(0, 24)}…` : b64;
    return { kind: 'binary', display: `BinData(${parseInt(sub, 16) || 0}, "${preview}")`, detail: `${len} bytes, subtype 0x${sub}` };
  }
  if (only(v, '$uuid') && typeof v.$uuid === 'string') return { kind: 'uuid', display: `UUID("${v.$uuid}")` };
  if (only(v, '$timestamp') && isObj(v.$timestamp))
    return { kind: 'timestamp', display: `Timestamp(${String(v.$timestamp.t)}, ${String(v.$timestamp.i)})` };
  if (only(v, '$regularExpression') && isObj(v.$regularExpression))
    return {
      kind: 'regex',
      display: `/${String(v.$regularExpression.pattern)}/${String(v.$regularExpression.options ?? '')}`,
    };
  if (only(v, '$minKey')) return { kind: 'minKey', display: 'MinKey()' };
  if (only(v, '$maxKey')) return { kind: 'maxKey', display: 'MaxKey()' };
  if (only(v, '$symbol')) return { kind: 'symbol', display: `Symbol("${String(v.$symbol)}")` };
  if (only(v, '$code') || only(v, '$code', '$scope')) return { kind: 'code', display: `Code(${JSON.stringify(v.$code)})` };
  if (only(v, '$dbPointer')) return { kind: 'dbPointer', display: 'DBPointer(…)' };
  if (only(v, '$undefined')) return { kind: 'undefined', display: 'undefined' };
  return null;
}

/** One-line summary of a value for collapsed displays. */
export function summarize(v: unknown, max = 80): string {
  const b = detectBson(v);
  if (b) return b.display;
  if (Array.isArray(v)) return `Array(${v.length})`;
  if (isObj(v)) return `{ ${Object.keys(v).length} fields }`;
  const s = typeof v === 'string' ? JSON.stringify(v) : String(v);
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

const shellFns: Record<string, (arg: string) => string> = {
  ObjectId: (a) => `{"$oid": ${a}}`,
  ISODate: (a) => `{"$date": ${a}}`,
  NumberDecimal: (a) => `{"$numberDecimal": ${quote(a)}}`,
  NumberLong: (a) => `{"$numberLong": ${quote(a)}}`,
  NumberInt: (a) => `{"$numberInt": ${quote(a)}}`,
  UUID: (a) => `{"$uuid": ${a}}`,
};

function quote(a: string): string {
  const t = a.trim();
  return t.startsWith('"') ? t : JSON.stringify(t);
}

/**
 * Converts common mongo-shell helpers (ObjectId("…"), ISODate("…"),
 * NumberDecimal("…"), NumberLong(…), NumberInt(…), UUID("…"), new Date("…"))
 * into Extended JSON. String literals are left untouched.
 */
export function shellToExtJSON(text: string): string {
  let out = '';
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === '"' || c === "'") {
      const end = scanString(text, i);
      const lit = text.slice(i, end);
      out += c === "'" ? JSON.stringify(unescapeSingle(lit.slice(1, -1))) : lit;
      i = end;
      continue;
    }
    if (/[A-Za-z_$]/.test(c) && (i === 0 || !/[\w$]/.test(text[i - 1]))) {
      // Unquoted object key ({status: "A"}) following "{" or ",".
      const prev = out.trimEnd().slice(-1);
      if (prev === '{' || prev === ',') {
        const k = /^([A-Za-z_$][\w$.]*)\s*:/.exec(text.slice(i));
        if (k) {
          out += `${JSON.stringify(k[1])}:`;
          i += k[0].length;
          continue;
        }
      }
      const m = /^(new\s+Date|ObjectId|ISODate|NumberDecimal|NumberLong|NumberInt|UUID)\s*\(/.exec(text.slice(i));
      if (m) {
        const start = i + m[0].length;
        const close = findClose(text, start);
        if (close > 0) {
          let arg = text.slice(start, close).trim();
          if (arg.startsWith("'")) arg = JSON.stringify(unescapeSingle(arg.slice(1, -1)));
          const fn = m[1].startsWith('new') ? shellFns.ISODate : shellFns[m[1]];
          out += fn(arg);
          i = close + 1;
          continue;
        }
      }
    }
    out += c;
    i++;
  }
  return out;
}

function scanString(s: string, start: number): number {
  const q = s[start];
  let i = start + 1;
  while (i < s.length) {
    if (s[i] === '\\') i += 2;
    else if (s[i] === q) return i + 1;
    else i++;
  }
  return s.length;
}

function unescapeSingle(s: string): string {
  return s.replace(/\\'/g, "'").replace(/\\\\/g, '\\');
}

function findClose(s: string, start: number): number {
  let depth = 0;
  for (let i = start; i < s.length; i++) {
    const c = s[i];
    if (c === '"' || c === "'") {
      i = scanString(s, i) - 1;
      continue;
    }
    if (c === '(') depth++;
    if (c === ')') {
      if (depth === 0) return i;
      depth--;
    }
  }
  return -1;
}

/** Normalises user input to Extended JSON and checks it is a JSON object or array. */
export function normalizeInput(text: string, want: 'object' | 'array'): { value: string; error?: string } {
  const t = text.trim();
  if (!t) return { value: '' };
  const converted = shellToExtJSON(t);
  try {
    const parsed: unknown = JSON.parse(converted);
    if (want === 'object' && !isObj(parsed)) return { value: converted, error: 'Expected a JSON object { … }' };
    if (want === 'array' && !Array.isArray(parsed)) return { value: converted, error: 'Expected a JSON array [ … ]' };
    return { value: converted };
  } catch (e) {
    return { value: converted, error: e instanceof Error ? e.message : 'Invalid JSON' };
  }
}

export function formatBytes(n: unknown): string {
  const v = typeof n === 'number' ? n : Number(n);
  if (!Number.isFinite(v)) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let x = v;
  let u = 0;
  while (x >= 1024 && u < units.length - 1) {
    x /= 1024;
    u++;
  }
  return `${x.toFixed(u === 0 ? 0 : 1)} ${units[u]}`;
}

/** Reads a numeric value that may be relaxed or wrapped Extended JSON. */
export function num(v: unknown): number | undefined {
  if (typeof v === 'number') return v;
  if (isObj(v)) {
    for (const k of ['$numberInt', '$numberLong', '$numberDouble', '$numberDecimal']) {
      if (typeof v[k] === 'string') return Number(v[k]);
    }
  }
  return undefined;
}
