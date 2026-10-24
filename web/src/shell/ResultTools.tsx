import { useMemo, useState } from 'react';
import { Button, Label, ToggleGroup, ToggleGroupItem, Tooltip } from '@patternfly/react-core';
import { DownloadIcon } from '@patternfly/react-icons';
import type { DisplayValue } from '../sandbox/display';
import { summarize } from '../lib/ejson';
import { ShellValue } from './ShellOutput';

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

/** The documents of a result, when it is a cursor page, an array of documents or one document. */
export function resultDocuments(outputs: DisplayValue[]): Obj[] | null {
  for (const o of outputs) {
    const v = o.value;
    if (o.text || v === null || typeof v !== 'object') continue;
    if (o.type && /Cursor/.test(o.type) && isObj(v) && Array.isArray((v as { documents?: unknown }).documents)) {
      const docs = (v as { documents: unknown[] }).documents.filter(isObj);
      return docs.length ? docs : null;
    }
    if (Array.isArray(v) && v.length > 0 && v.every(isObj)) return v as Obj[];
    if ((o.type === 'Document' || o.type === null) && isObj(v) && !('queryPlanner' in v)) return [v];
  }
  return null;
}

function explainOf(outputs: DisplayValue[]): Obj | null {
  for (const o of outputs) {
    if (isObj(o.value) && ('queryPlanner' in o.value || 'stages' in o.value)) return o.value;
  }
  return null;
}

function columns(docs: Obj[]): string[] {
  const seen: string[] = [];
  for (const d of docs.slice(0, 200)) for (const k of Object.keys(d)) if (!seen.includes(k)) seen.push(k);
  return seen.slice(0, 40);
}

function n(v: unknown): number | undefined {
  if (typeof v === 'number') return v;
  if (isObj(v)) {
    const x = v.$numberInt ?? v.$numberLong ?? v.$numberDouble;
    if (typeof x === 'string') return Number(x);
  }
  return undefined;
}

function stageChain(plan: unknown): string[] {
  const out: string[] = [];
  let p = plan;
  for (let i = 0; i < 20 && isObj(p); i++) {
    const s = p.stage;
    if (typeof s === 'string') {
      const idx = typeof p.indexName === 'string' ? ` (${p.indexName})` : '';
      out.push(s + idx);
    }
    p = p.inputStage ?? (Array.isArray(p.inputStages) ? p.inputStages[0] : undefined);
  }
  return out;
}

/** A readable summary of explain() output: plan stages and work done. */
export function ExplainSummary({ explain }: { explain: Obj }) {
  const qp = isObj(explain.queryPlanner) ? explain.queryPlanner : isObj((explain.stages as Obj[] | undefined)?.[0]?.$cursor) ? ((explain.stages as Obj[])[0].$cursor as Obj).queryPlanner : undefined;
  const es = isObj(explain.executionStats) ? explain.executionStats : undefined;
  const winning = isObj(qp) ? (qp as Obj).winningPlan : undefined;
  const chain = stageChain(isObj(winning) && isObj(winning.queryPlan) ? winning.queryPlan : winning);
  const collscan = chain.some((s) => s.startsWith('COLLSCAN'));
  const returned = n(es?.nReturned);
  const keys = n(es?.totalKeysExamined);
  const docs = n(es?.totalDocsExamined);
  return (
    <div className="portal-explain" aria-label="Explain summary">
      <div>
        <strong>Plan</strong>{' '}
        {chain.length ? chain.reverse().join(' → ') : 'not available'}{' '}
        {collscan && (
          <Label isCompact color="orange">
            collection scan
          </Label>
        )}
      </div>
      {es && (
        <div className="portal-small">
          {returned ?? '—'} returned · {keys ?? '—'} keys examined · {docs ?? '—'} documents examined · {n(es.executionTimeMillis) ?? '—'} ms
          {returned !== undefined && docs !== undefined && returned > 0 && docs / returned > 10 && (
            <Label isCompact color="orange" className="pf-v6-u-ml-sm">
              {Math.round(docs / returned)}× more documents examined than returned
            </Label>
          )}
        </div>
      )}
    </div>
  );
}

function download(name: string, type: string, body: string) {
  const url = URL.createObjectURL(new Blob([body], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

function cellText(v: unknown, max: number): string {
  if (v === undefined) return '';
  return typeof v === 'string' ? (v.length > max ? `${v.slice(0, max)}…` : v) : summarize(v, max);
}

function csvCell(v: unknown): string {
  const s = typeof v === 'string' ? v : v === undefined || v === null ? '' : summarize(v, 10_000);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

type View = 'rich' | 'table' | 'json';

/** Renders one entry's outputs with view switches and downloads. */
export function EntryResult({ outputs }: { outputs: DisplayValue[] }) {
  const [view, setView] = useState<View>('rich');
  const docs = useMemo(() => resultDocuments(outputs), [outputs]);
  const explain = useMemo(() => explainOf(outputs), [outputs]);
  const cols = useMemo(() => (docs ? columns(docs) : []), [docs]);
  if (outputs.length === 0) return null;
  const json = () => JSON.stringify(docs ?? outputs.map((o) => o.value), null, 2);
  return (
    <>
      {explain && <ExplainSummary explain={explain} />}
      {(docs || explain) && (
        <div className="portal-result-tools">
          <ToggleGroup isCompact aria-label="Result view">
            <ToggleGroupItem text="Documents" isSelected={view === 'rich'} onChange={() => setView('rich')} />
            {docs && <ToggleGroupItem text="Table" isSelected={view === 'table'} onChange={() => setView('table')} />}
            <ToggleGroupItem text="JSON" isSelected={view === 'json'} onChange={() => setView('json')} />
          </ToggleGroup>
          <Tooltip content="Download as Extended JSON">
            <Button variant="plain" size="sm" aria-label="Download result as JSON" icon={<DownloadIcon />} onClick={() => download('result.json', 'application/json', json())}>
              JSON
            </Button>
          </Tooltip>
          {docs && (
            <Tooltip content="Download as CSV (this page of results)">
              <Button
                variant="plain"
                size="sm"
                aria-label="Download result as CSV"
                icon={<DownloadIcon />}
                onClick={() => download('result.csv', 'text/csv', [cols.join(','), ...docs.map((d) => cols.map((c) => csvCell(d[c])).join(','))].join('\n'))}
              >
                CSV
              </Button>
            </Tooltip>
          )}
        </div>
      )}
      {view === 'rich' &&
        outputs.map((o, i) => (
          <div key={i} className="portal-shell-out">
            <ShellValue d={o} />
          </div>
        ))}
      {view === 'table' && docs && (
        <div className="portal-shell-out portal-result-table">
          <table>
            <thead>
              <tr>
                {cols.map((c) => (
                  <th key={c}>{c}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {docs.map((d, i) => (
                <tr key={i}>
                  {cols.map((c) => (
                    <td key={c} title={cellText(d[c], 2000)}>
                      {cellText(d[c], 80)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {view === 'json' && (
        <div className="portal-shell-out">
          <pre className="portal-shell-pre">{json()}</pre>
        </div>
      )}
    </>
  );
}
