// Minimal JavaScript tokenizer for highlighting mongosh input. It only
// classifies text for display (rendered as React text nodes, never HTML).

export type TokenKind = 'keyword' | 'builtin' | 'string' | 'number' | 'comment' | 'operator' | 'property' | 'text';

export interface Token {
  kind: TokenKind;
  text: string;
}

const KEYWORDS = new Set([
  'const', 'let', 'var', 'function', 'return', 'if', 'else', 'for', 'while', 'do', 'of', 'in', 'new', 'await', 'async',
  'true', 'false', 'null', 'undefined', 'typeof', 'try', 'catch', 'finally', 'throw', 'break', 'continue', 'switch', 'case',
]);

const BUILTINS = new Set([
  'db', 'rs', 'sh', 'use', 'show', 'it', 'print', 'printjson', 'help', 'exit', 'quit', 'cls',
  'ObjectId', 'ISODate', 'Date', 'NumberLong', 'NumberInt', 'NumberDecimal', 'UUID', 'BinData', 'Timestamp', 'MinKey', 'MaxKey',
  'JSON', 'Math', 'Object', 'Array', 'String', 'Number',
]);

const re = /(\/\/[^\n]*)|("(?:[^"\\\n]|\\.)*"?|'(?:[^'\\\n]|\\.)*'?|`(?:[^`\\]|\\.)*`?)|(\b\d+(?:\.\d+)?(?:e[+-]?\d+)?\b)|([A-Za-z_$][\w$]*)|([{}()[\];,.:?=+\-*/%<>!&|^~]+)|(\s+)|(.)/gy;

/** Splits code into tokens; concatenating the token texts gives the input back. */
export function tokenize(code: string): Token[] {
  const out: Token[] = [];
  re.lastIndex = 0;
  let prevText = '';
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    const [text, comment, str, number, ident, op] = m;
    let kind: TokenKind = 'text';
    if (comment) kind = 'comment';
    else if (str) kind = 'string';
    else if (number) kind = 'number';
    else if (ident) {
      if (KEYWORDS.has(ident)) kind = 'keyword';
      else if (prevText.endsWith('.')) kind = 'property';
      else if (BUILTINS.has(ident)) kind = 'builtin';
    } else if (op) kind = 'operator';
    const last = out[out.length - 1];
    if (last && last.kind === kind && kind === 'text') last.text += text;
    else out.push({ kind, text });
    if (text.trim()) prevText = text;
    if (re.lastIndex >= code.length) break;
  }
  return out;
}
