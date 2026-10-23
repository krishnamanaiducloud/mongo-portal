import { useState } from 'react';
import { detectBson, summarize } from '../lib/ejson';

type Json = unknown;

const LONG_STRING = 300;

/** BSON-aware, keyboard accessible tree view of a canonical Extended JSON document. */
export function DocumentView({ doc, expandDepth = 1 }: { doc: Record<string, Json>; expandDepth?: number }) {
  return (
    <div className="ejson" role="tree" aria-label="Document">
      <ObjectBody value={doc} depth={0} expandDepth={expandDepth} />
    </div>
  );
}

function ObjectBody({ value, depth, expandDepth }: { value: Record<string, Json>; depth: number; expandDepth: number }) {
  return (
    <ul className="ejson-list">
      {Object.entries(value).map(([k, v]) => (
        <Field key={k} name={k} value={v} depth={depth} expandDepth={expandDepth} />
      ))}
    </ul>
  );
}

function Field({ name, value, depth, expandDepth }: { name: string; value: Json; depth: number; expandDepth: number }) {
  const bson = detectBson(value);
  const container = !bson && typeof value === 'object' && value !== null;
  const [open, setOpen] = useState(depth < expandDepth);

  if (!container) {
    return (
      <li className="ejson-row" role="treeitem" aria-selected={false}>
        <span className="ejson-key">{name}</span>
        <span className="ejson-colon">: </span>
        <Scalar value={value} />
      </li>
    );
  }
  const isArray = Array.isArray(value);
  const size = isArray ? (value as Json[]).length : Object.keys(value as object).length;
  return (
    <li className="ejson-row" role="treeitem" aria-expanded={open} aria-selected={false}>
      <button type="button" className="ejson-toggle" onClick={() => setOpen((o) => !o)} aria-label={`${open ? 'Collapse' : 'Expand'} ${name}`}>
        {open ? '▾' : '▸'}
      </button>
      <span className="ejson-key">{name}</span>
      <span className="ejson-colon">: </span>
      {!open && <span className="ejson-summary">{isArray ? `Array(${size})` : `{ ${size} fields }`}</span>}
      {open &&
        (isArray ? (
          <ul className="ejson-list" role="group">
            {(value as Json[]).map((v, i) => (
              <Field key={i} name={String(i)} value={v} depth={depth + 1} expandDepth={expandDepth} />
            ))}
          </ul>
        ) : (
          <div role="group">
            <ObjectBody value={value as Record<string, Json>} depth={depth + 1} expandDepth={expandDepth} />
          </div>
        ))}
    </li>
  );
}

function Scalar({ value }: { value: Json }) {
  const [expanded, setExpanded] = useState(false);
  const bson = detectBson(value);
  if (bson) {
    return (
      <span className={`ejson-bson ejson-${bson.kind}`} title={bson.detail ?? bson.kind}>
        {bson.display}
      </span>
    );
  }
  if (value === null) return <span className="ejson-null">null</span>;
  if (typeof value === 'boolean') return <span className="ejson-bool">{String(value)}</span>;
  if (typeof value === 'number') return <span className="ejson-number">{String(value)}</span>;
  if (typeof value === 'string') {
    if (value.length > LONG_STRING && !expanded) {
      return (
        <>
          <span className="ejson-string">{JSON.stringify(value.slice(0, LONG_STRING))}…</span>{' '}
          <button type="button" className="ejson-more" onClick={() => setExpanded(true)}>
            show all ({value.length} chars)
          </button>
        </>
      );
    }
    return <span className="ejson-string">{JSON.stringify(value)}</span>;
  }
  return <span>{summarize(value)}</span>;
}
