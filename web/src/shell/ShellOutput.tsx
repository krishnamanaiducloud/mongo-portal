import type { DisplayError, DisplayValue } from '../sandbox/display';
import { DocumentView } from '../components/DocumentView';
import { detectBson, formatBytes, num } from '../lib/ejson';

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

function Docs({ docs }: { docs: unknown[] }) {
  if (docs.length === 0) return <span className="portal-shell-muted">(no documents)</span>;
  return (
    <>
      {docs.map((d, i) => (
        <div key={i} className="portal-shell-doc">
          <Value v={d} />
        </div>
      ))}
    </>
  );
}

function Value({ v }: { v: unknown }) {
  const b = detectBson(v);
  if (b) return <span className={`ejson ejson-bson ejson-${b.kind}`}>{b.display}</span>;
  if (isObj(v)) return <DocumentView doc={v} expandDepth={2} />;
  if (Array.isArray(v)) {
    if (v.length > 0 && v.every((x) => isObj(x) && !detectBson(x))) return <Docs docs={v} />;
    return <pre className="portal-shell-pre">{JSON.stringify(v, null, 2)}</pre>;
  }
  return <pre className="portal-shell-pre">{typeof v === 'string' ? v : JSON.stringify(v)}</pre>;
}

/** Renders one mongosh result the way mongosh prints it, BSON-aware. */
export function ShellValue({ d }: { d: DisplayValue }) {
  const v = d.value;
  if (d.text || typeof v === 'string') return <pre className="portal-shell-pre">{String(v)}</pre>;
  if (v === null || typeof v !== 'object') return <pre className="portal-shell-pre">{String(v)}</pre>;
  switch (d.type) {
    case 'Cursor':
    case 'AggregationCursor':
    case 'RunCommandCursor':
    case 'CursorIterationResult': {
      const c = v as { documents?: unknown[]; cursorHasMore?: boolean };
      return (
        <>
          <Docs docs={c.documents ?? []} />
          {c.cursorHasMore && <div className="portal-shell-muted">Type &quot;it&quot; for more</div>}
        </>
      );
    }
    case 'Help': {
      const h = v as { help?: string; docs?: string; attr?: { name?: string; description?: string }[] };
      return (
        <div>
          {h.help && <div className="pf-v6-u-mb-sm">{h.help}</div>}
          {h.attr && (
            <table className="portal-shell-table">
              <tbody>
                {h.attr.map((a, i) => (
                  <tr key={i}>
                    <td className="portal-shell-help-name">{a.name}</td>
                    <td>{a.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {h.docs && <div className="portal-shell-muted pf-v6-u-mt-sm">For more information, see {h.docs}</div>}
        </div>
      );
    }
    case 'ShowDatabasesResult': {
      const rows = Array.isArray(v) ? (v as Obj[]) : [];
      const width = Math.max(0, ...rows.map((r) => String(r.name).length));
      return (
        <pre className="portal-shell-pre">
          {rows.map((r) => `${String(r.name).padEnd(width + 2)}${r.sizeOnDisk !== undefined ? formatBytes(num(r.sizeOnDisk)) : ''}`).join('\n')}
        </pre>
      );
    }
    case 'ShowCollectionsResult': {
      const rows = Array.isArray(v) ? (v as Obj[]) : [];
      return <pre className="portal-shell-pre">{rows.map((r) => `${String(r.name)}${r.badge ? `  ${String(r.badge)}` : ''}`).join('\n')}</pre>;
    }
  }
  return <Value v={v} />;
}

export function ShellError({ e }: { e: DisplayError }) {
  const label = e.codeName ? `${e.name}[${e.codeName}]` : e.name;
  return (
    <div className="portal-shell-error">
      {label}: {e.message}
    </div>
  );
}
