import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router';
import {
  Alert,
  Button,
  Checkbox,
  Content,
  Flex,
  Form,
  FormGroup,
  Label,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalVariant,
  PageSection,
  SearchInput,
  Spinner,
  Tab,
  Tabs,
  TabTitleText,
  TextInput,
  Title,
  Tooltip,
} from '@patternfly/react-core';
import {
  CheckCircleIcon,
  CheckIcon,
  CopyIcon,
  DownloadIcon,
  ExclamationCircleIcon,
  HistoryIcon,
  InProgressIcon,
  PencilAltIcon,
  RedoIcon,
  ColumnsIcon,
  OutlinedStarIcon,
  StarIcon,
  TrashIcon,
} from '@patternfly/react-icons';
import { useSession } from '../api/hooks';
import { tokenize } from '../lib/highlight';
import type { DisplayError, DisplayValue } from '../sandbox/display';
import { ShellBroker, type ConfirmDecision, type ConfirmRequest } from '../shell/broker';
import { ShellError } from '../shell/ShellOutput';
import { EntryResult } from '../shell/ResultTools';

interface Entry {
  id: number;
  prompt: string;
  code: string;
  outputs: DisplayValue[];
  error?: DisplayError;
  running: boolean;
  started: number;
  ms?: number;
}

type Status = 'starting' | 'ready' | 'failed';

interface Snippet {
  label: string;
  code: string;
  /** Text selected after inserting, so typing replaces the placeholder. */
  select?: string;
}

const SNIPPETS: { group: string; items: Snippet[] }[] = [
  {
    group: 'Explore',
    items: [
      { label: 'List databases', code: 'show dbs' },
      { label: 'List collections', code: 'show collections' },
      { label: 'Database statistics', code: 'db.stats()' },
      { label: 'Collection statistics', code: 'db.getCollection("collection").stats()', select: 'collection' },
    ],
  },
  {
    group: 'Query',
    items: [
      { label: 'Find documents', code: 'db.getCollection("collection").find({}).limit(20)', select: 'collection' },
      { label: 'Count documents', code: 'db.getCollection("collection").countDocuments({})', select: 'collection' },
      { label: 'Distinct values', code: 'db.getCollection("collection").distinct("field")', select: 'collection' },
      {
        label: 'Group and count',
        code: 'db.getCollection("collection").aggregate([\n  { $group: { _id: "$field", count: { $sum: 1 } } },\n  { $sort: { count: -1 } },\n  { $limit: 10 }\n])',
        select: 'collection',
      },
      { label: 'Explain a query', code: 'db.getCollection("collection").find({}).explain("executionStats")', select: 'collection' },
    ],
  },
  {
    group: 'Indexes',
    items: [
      { label: 'List indexes', code: 'db.getCollection("collection").getIndexes()', select: 'collection' },
      { label: 'Index sizes', code: 'db.getCollection("collection").stats().indexSizes', select: 'collection' },
    ],
  },
  {
    group: 'Server',
    items: [
      { label: 'Server version', code: 'db.version()' },
      { label: 'Who am I', code: 'db.runCommand({ connectionStatus: 1 }).authInfo' },
      { label: 'Replica set status', code: 'rs.status().members.map(m => ({ name: m.name, state: m.stateStr, health: m.health }))' },
      { label: 'Connections', code: 'db.serverStatus().connections' },
    ],
  },
  {
    group: 'Diagnostics',
    items: [
      { label: 'Current operations (slow first)', code: 'db.currentOp({ active: true, secs_running: { $gte: 1 } }).inprog.map(o => ({ opid: o.opid, op: o.op, ns: o.ns, secs: o.secs_running, client: o.client }))' },
      { label: 'Replication lag', code: 'rs.printSecondaryReplicationInfo()' },
      { label: 'Oplog window', code: 'rs.printReplicationInfo()' },
      { label: 'WiredTiger cache', code: 'db.serverStatus().wiredTiger.cache' },
      { label: 'Profiler status', code: 'db.getProfilingStatus()' },
      { label: 'Slowest profiled queries', code: 'db.system.profile.find().sort({ millis: -1 }).limit(10)' },
      { label: 'Index usage', code: 'db.getCollection("collection").aggregate([{ $indexStats: {} }])', select: 'collection' },
      { label: 'Explain an aggregation', code: 'db.getCollection("collection").explain("executionStats").aggregate([{ $match: {} }])', select: 'collection' },
    ],
  },
];

// Saved snippets are the user's own queries, kept in this browser only
// (no credentials or results). Removing site data removes them.
interface SavedSnippet {
  name: string;
  code: string;
}
const SAVED_KEY = 'mongo-portal-shell-snippets';

function loadSaved(): SavedSnippet[] {
  try {
    const v = JSON.parse(localStorage.getItem(SAVED_KEY) ?? '[]') as unknown;
    return Array.isArray(v) ? v.filter((x): x is SavedSnippet => typeof x?.name === 'string' && typeof x?.code === 'string').slice(0, 200) : [];
  } catch {
    return [];
  }
}

function storeSaved(list: SavedSnippet[]) {
  try {
    localStorage.setItem(SAVED_KEY, JSON.stringify(list.slice(0, 200)));
  } catch {
    // storage unavailable (private mode): snippets last for this page only
  }
}

const SHORTCUTS: [string, string][] = [
  ['Enter', 'Run'],
  ['Shift + Enter', 'New line'],
  ['Tab', 'Complete'],
  ['↑ / ↓', 'History'],
  ['Ctrl + C', 'Interrupt a running command'],
  ['Ctrl + L', 'Clear the console'],
  ['Esc', 'Close completions'],
];

function Highlighted({ code }: { code: string }) {
  return (
    <>
      {tokenize(code).map((t, i) => (t.kind === 'text' ? t.text : <span key={i} className={`portal-tok-${t.kind}`}>{t.text}</span>))}
    </>
  );
}

function formatMs(ms: number) {
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(ms < 10_000 ? 2 : 1)} s`;
  return `${Math.floor(ms / 60_000)} min ${Math.round((ms % 60_000) / 1000)} s`;
}

function valueText(d: DisplayValue): string {
  if (d.text || typeof d.value === 'string') return String(d.value);
  try {
    return JSON.stringify(d.value, null, 2);
  } catch {
    return String(d.value);
  }
}

function transcript(entries: Entry[]): string {
  return entries
    .map((e) => {
      const lines = [`${e.prompt} ${e.code}`, ...e.outputs.map(valueText)];
      if (e.error) lines.push(`${e.error.name}: ${e.error.message}`);
      return lines.join('\n');
    })
    .join('\n\n');
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** Icon button that confirms a copy with a check mark for a moment. */
function CopyButton({ text, label }: { text: () => string; label: string }) {
  const [done, setDone] = useState(false);
  useEffect(() => {
    if (!done) return;
    const t = setTimeout(() => setDone(false), 1500);
    return () => clearTimeout(t);
  }, [done]);
  return (
    <Tooltip content={done ? 'Copied' : label}>
      <Button
        variant="plain"
        size="sm"
        aria-label={done ? 'Copied' : label}
        icon={done ? <CheckIcon /> : <CopyIcon />}
        onClick={() => void copyText(text()).then(setDone)}
      />
    </Tooltip>
  );
}

export function ShellPage() {
  const [params] = useSearchParams();
  const session = useSession();
  // UI hint: whether RBAC allows any change anywhere. Each operation is
  // checked by the portal against its namespace and by MongoDB.
  const perms = session.data?.permissions ?? {};
  const canWrite = ['documents:create', 'documents:update', 'documents:delete', 'indexes:create', 'indexes:delete', 'collections:create', 'collections:delete', 'databases:delete'].some((k) => perms[k]);
  const profile = session.data?.profile ?? 'portal';
  const mongoUser = session.data?.mongoUser ?? '';
  const initialDb = params.get('db') || 'test';
  const hasSession = !!session.data;

  const frameHost = useRef<HTMLDivElement>(null);
  const broker = useRef<ShellBroker | null>(null);
  const current = useRef<number | null>(null);
  const nextId = useRef(1);
  const endRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const pendingSelect = useRef<string | undefined>(undefined);

  const [generation, setGeneration] = useState(0);
  const [status, setStatus] = useState<Status>('starting');
  const [startError, setStartError] = useState<string>();
  const [prompt, setPrompt] = useState('>');
  const [version, setVersion] = useState('');
  const [entries, setEntries] = useState<Entry[]>([]);
  const [input, setInput] = useState('');
  const [history, setHistory] = useState<string[]>([]);
  const [histPos, setHistPos] = useState(-1);
  const [busy, setBusy] = useState(false);
  const [completions, setCompletions] = useState<string[]>([]);
  const [selected, setSelected] = useState(-1);
  const [completing, setCompleting] = useState(false);
  const [confirmReq, setConfirmReq] = useState<{ req: ConfirmRequest; resolve: (d: ConfirmDecision) => void } | null>(null);
  const [panel, setPanel] = useState(true);
  const [panelTab, setPanelTab] = useState<string | number>('snippets');
  const [saved, setSaved] = useState<SavedSnippet[]>(loadSaved);
  const [historyFilter, setHistoryFilter] = useState('');
  const [saveName, setSaveName] = useState<string>();
  const saveSnippet = (name: string, code: string) => {
    const next = [{ name: name.trim() || code.slice(0, 40), code }, ...saved.filter((s) => s.code !== code)];
    setSaved(next);
    storeSaved(next);
  };
  const removeSnippet = (code: string) => {
    const next = saved.filter((s) => s.code !== code);
    setSaved(next);
    storeSaved(next);
  };

  const patch = useCallback((id: number, f: (e: Entry) => Entry) => {
    setEntries((es) => es.map((e) => (e.id === id ? f(e) : e)));
  }, []);

  // Start (or restart) the sandbox.
  useEffect(() => {
    const host = frameHost.current;
    if (!host || !hasSession) return;
    const b = new ShellBroker({
      canWrite,
      confirm: (req) => new Promise<ConfirmDecision>((resolve) => setConfirmReq({ req, resolve })),
      onPrint: (values) => {
        const id = current.current;
        if (id !== null) patch(id, (e) => ({ ...e, outputs: [...e.outputs, ...values].slice(-2000) }));
      },
      onClear: () => setEntries([]),
      onExit: () => setGeneration((g) => g + 1),
    });
    broker.current = b;
    setStatus('starting');
    setStartError(undefined);
    b.start(host, initialDb, `mongodb://${profile}.portal/`).then(
      (r) => {
        setPrompt(r.prompt);
        setVersion(r.version);
        setStatus('ready');
      },
      (e: unknown) => {
        setStatus('failed');
        setStartError(e instanceof Error ? e.message : 'The shell failed to start');
      },
    );
    return () => {
      b.destroy();
      broker.current = null;
    };
  }, [generation, hasSession, canWrite, initialDb, profile, patch]);

  useEffect(() => {
    endRef.current?.scrollIntoView?.({ block: 'end' });
  }, [entries]);

  // Grow the input with its content, and apply a pending snippet selection.
  useLayoutEffect(() => {
    const el = inputRef.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${el.scrollHeight}px`;
    const sel = pendingSelect.current;
    if (sel !== undefined) {
      pendingSelect.current = undefined;
      const at = sel ? el.value.indexOf(sel) : -1;
      el.focus();
      if (at >= 0) el.setSelectionRange(at, at + sel.length);
      else el.setSelectionRange(el.value.length, el.value.length);
    }
  }, [input]);

  const insert = (code: string, select?: string) => {
    setCompletions([]);
    setHistPos(-1);
    if (code === input) {
      const el = inputRef.current;
      const at = select ? code.indexOf(select) : -1;
      el?.focus();
      if (at >= 0) el?.setSelectionRange(at, at + (select?.length ?? 0));
      return;
    }
    pendingSelect.current = select ?? '';
    setInput(code);
  };

  const run = async (text = input) => {
    const code = text.trim();
    if (!code || busy || status !== 'ready' || !broker.current) return;
    setInput('');
    setCompletions([]);
    setHistory((h) => (h[h.length - 1] === code ? h : [...h.slice(-199), code]));
    setHistPos(-1);
    const id = nextId.current++;
    current.current = id;
    const started = performance.now();
    setEntries((es) => [...es, { id, prompt, code, outputs: [], running: true, started }].slice(-300));
    setBusy(true);
    const r = await broker.current.evaluate(code);
    current.current = null;
    setBusy(false);
    setPrompt(r.prompt || prompt);
    patch(id, (e) => ({
      ...e,
      running: false,
      ms: performance.now() - started,
      outputs: r.ok && r.value && !(r.value.type === null && r.value.value === 'undefined') ? [...e.outputs, r.value] : e.outputs,
      error: r.ok ? undefined : r.error,
    }));
    inputRef.current?.focus();
  };

  const accept = (c: string) => {
    setInput(c);
    setCompletions([]);
    setSelected(-1);
    inputRef.current?.focus();
  };

  const complete = async () => {
    if (!broker.current || status !== 'ready' || completing) return;
    setCompleting(true);
    const list = await broker.current.complete(input).finally(() => setCompleting(false));
    if (list.length === 1) {
      accept(list[0]);
      return;
    }
    // Extend to the longest common prefix, then offer the choices.
    let prefix = list[0] ?? '';
    for (const c of list) while (!c.startsWith(prefix)) prefix = prefix.slice(0, -1);
    if (prefix.length > input.length) setInput(prefix);
    setCompletions(list);
    setSelected(-1);
  };

  const reset = () => {
    setEntries((es) =>
      es.map((x) => (x.running ? { ...x, running: false, ms: performance.now() - x.started, error: { name: 'Interrupted', message: 'Execution was interrupted and the shell was restarted' } } : x)),
    );
    setBusy(false);
    current.current = null;
    setGeneration((g) => g + 1);
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    const el = e.currentTarget;
    const open = completions.length > 1;
    if (open && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
      e.preventDefault();
      const n = completions.length;
      setSelected((s) => (e.key === 'ArrowDown' ? (s + 1) % n : (s - 1 + n) % n));
    } else if (open && selected >= 0 && (e.key === 'Enter' || e.key === 'Tab')) {
      e.preventDefault();
      accept(completions[selected]);
    } else if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      void run();
    } else if (e.key === 'Tab' && !e.shiftKey) {
      e.preventDefault();
      if (open) setSelected((s) => (s + 1) % completions.length);
      else void complete();
    } else if (e.key === 'Escape') {
      setCompletions([]);
    } else if (e.key === 'ArrowUp' && el.selectionStart === 0 && el.selectionEnd === 0 && history.length) {
      e.preventDefault();
      const pos = histPos < 0 ? history.length - 1 : Math.max(0, histPos - 1);
      setHistPos(pos);
      setInput(history[pos]);
    } else if (e.key === 'ArrowDown' && histPos >= 0 && el.selectionEnd === el.value.length) {
      e.preventDefault();
      const pos = histPos + 1;
      setHistPos(pos >= history.length ? -1 : pos);
      setInput(pos >= history.length ? '' : history[pos]);
    } else if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault();
      setEntries([]);
    } else if (e.key === 'c' && e.ctrlKey && busy && el.selectionStart === el.selectionEnd) {
      e.preventDefault();
      reset();
    }
  };

  const download = () => {
    const blob = new Blob([transcript(entries)], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mongosh-${profile}-${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const state = status === 'failed' ? 'failed' : status === 'starting' ? 'starting' : busy ? 'busy' : 'ready';
  const stateLabel = { failed: 'Unavailable', starting: 'Starting', busy: 'Running', ready: 'Ready' }[state];
  const StateIcon = { failed: ExclamationCircleIcon, starting: InProgressIcon, busy: InProgressIcon, ready: CheckCircleIcon }[state];

  return (
    <PageSection>
      <Flex alignItems={{ default: 'alignItemsCenter' }} gap={{ default: 'gapSm' }} className="pf-v6-u-mb-xs">
        <Title headingLevel="h1">Shell</Title>
        {version && <Label isCompact>mongosh {version}</Label>}
      </Flex>
      <Content component="p" className="pf-v6-u-mb-md portal-shell-intro">
        The real mongosh runtime, isolated in your browser. Every database operation goes through the portal and is checked against your
        portal role and your MongoDB privileges.
      </Content>
      {!canWrite && (
        <Alert variant="info" isInline isPlain className="pf-v6-u-mb-sm" title="Your portal role is read-only: write operations are rejected." />
      )}
      {status === 'failed' && (
        <Alert variant="danger" isInline className="pf-v6-u-mb-sm" title={startError ?? 'The shell failed to start'}>
          <Button variant="link" isInline onClick={() => setGeneration((g) => g + 1)}>
            Try again
          </Button>
        </Alert>
      )}
      <div ref={frameHost} />
      <div className={`portal-shell-layout${panel ? ' has-panel' : ''}`}>
        <section className="portal-shell-console" aria-label="mongosh console">
          <header className="portal-shell-bar">
            <span className={`portal-shell-state is-${state}`}>
              <StateIcon aria-hidden /> {stateLabel}
            </span>
            {mongoUser && (
              <span className="portal-shell-chip portal-mono" title="MongoDB user and connection profile">
                {mongoUser}@{profile}
              </span>
            )}
            <span className="portal-shell-bar-actions">
              <CopyButton label="Copy transcript" text={() => transcript(entries)} />
              <Tooltip content="Download transcript">
                <Button variant="plain" size="sm" aria-label="Download transcript" icon={<DownloadIcon />} onClick={download} isDisabled={!entries.length} />
              </Tooltip>
              <Tooltip content="Clear console (Ctrl+L)">
                <Button variant="plain" size="sm" aria-label="Clear console" icon={<TrashIcon />} onClick={() => setEntries([])} isDisabled={!entries.length} />
              </Tooltip>
              <Button variant={busy ? 'warning' : 'secondary'} size="sm" onClick={reset} icon={busy ? undefined : <RedoIcon />}>
                {busy ? 'Interrupt' : 'Restart'}
              </Button>
              <Tooltip content={panel ? 'Hide side panel' : 'Show snippets, history and shortcuts'}>
                <Button variant="plain" size="sm" aria-label="Toggle side panel" aria-pressed={panel} icon={<ColumnsIcon />} onClick={() => setPanel((p) => !p)} />
              </Tooltip>
            </span>
          </header>
          <div
            className="portal-shell"
            onMouseUp={(e) => {
              // Focus the input on a click in empty space, but keep text selections.
              if (!window.getSelection()?.toString() && !(e.target as HTMLElement).closest('button, a, input, textarea, details, summary')) inputRef.current?.focus();
            }}
          >
            {status === 'starting' && (
              <div className="portal-shell-muted">
                <Spinner size="sm" aria-label="Starting" /> Starting mongosh…
              </div>
            )}
            {status === 'ready' && entries.length === 0 && (
              <div className="portal-shell-welcome">
                Connected to <strong>{profile}</strong>
                {mongoUser && (
                  <>
                    {' '}
                    as <strong>{mongoUser}</strong>
                  </>
                )}
                . Type <code>help</code> for commands, or pick a snippet.
              </div>
            )}
            <div role="log" aria-live="polite" aria-label="Shell output">
              {entries.map((en) => (
                <div key={en.id} className={`portal-shell-entry${en.error ? ' is-error' : ''}${en.running ? ' is-running' : ''}`}>
                  <div className="portal-shell-cmd">
                    <span className="portal-shell-prompt">{en.prompt}</span>
                    <code className="portal-shell-code">
                      <Highlighted code={en.code} />
                    </code>
                    <span className="portal-shell-meta">
                      {en.running ? <Spinner size="sm" aria-label="Running" /> : en.ms !== undefined && <span className="portal-shell-time">{formatMs(en.ms)}</span>}
                      <span className="portal-shell-entry-actions">
                        <CopyButton label="Copy command" text={() => en.code} />
                        <Tooltip content="Edit">
                          <Button variant="plain" size="sm" aria-label="Edit command" icon={<PencilAltIcon />} onClick={() => insert(en.code)} />
                        </Tooltip>
                        <Tooltip content="Run again">
                          <Button variant="plain" size="sm" aria-label="Run command again" icon={<RedoIcon />} isDisabled={busy || status !== 'ready'} onClick={() => void run(en.code)} />
                        </Tooltip>
                      </span>
                    </span>
                  </div>
                  <EntryResult outputs={en.outputs} />
                  {en.error && (
                    <div className="portal-shell-out">
                      <ShellError e={en.error} />
                    </div>
                  )}
                </div>
              ))}
            </div>
            <div className="portal-shell-input">
              <label htmlFor="shell-input" className="portal-shell-prompt">
                {prompt}
              </label>
              <div className="portal-shell-field">
                <textarea
                  id="shell-input"
                  ref={inputRef}
                  value={input}
                  onChange={(e) => {
                    setInput(e.target.value);
                    if (completions.length) setCompletions([]);
                  }}
                  onKeyDown={onKeyDown}
                  rows={1}
                  spellCheck={false}
                  autoComplete="off"
                  autoCapitalize="off"
                  aria-label="mongosh command. Enter runs, Shift+Enter inserts a new line, Tab completes."
                  aria-autocomplete="list"
                  aria-controls={completions.length > 1 ? 'shell-completions' : undefined}
                  aria-activedescendant={selected >= 0 && completions.length > 1 ? `shell-completion-${selected}` : undefined}
                  placeholder={status === 'ready' ? (busy ? 'Running… Ctrl+C interrupts' : 'db.collection.find({})') : ''}
                  disabled={status !== 'ready'}
                />
                {completing && <div className="portal-shell-muted portal-shell-completing">completing…</div>}
                {saveName !== undefined && (
                  <form
                    className="portal-shell-save"
                    onSubmit={(e) => {
                      e.preventDefault();
                      saveSnippet(saveName, input.trim());
                      setSaveName(undefined);
                      setPanelTab('snippets');
                    }}
                  >
                    <TextInput aria-label="Snippet name" placeholder="Snippet name" value={saveName} onChange={(_e, v) => setSaveName(v)} autoFocus />
                    <Button type="submit" size="sm" variant="secondary">
                      Save
                    </Button>
                    <Button size="sm" variant="link" onClick={() => setSaveName(undefined)}>
                      Cancel
                    </Button>
                  </form>
                )}
                {completions.length > 1 && (
                  <div id="shell-completions" className="portal-shell-completions" role="listbox" aria-label="Completions">
                    {completions.slice(0, 200).map((c, i) => (
                      <button
                        key={c}
                        id={`shell-completion-${i}`}
                        type="button"
                        role="option"
                        aria-selected={i === selected}
                        className="portal-shell-completion"
                        onMouseDown={(e) => e.preventDefault()}
                        onClick={() => accept(c)}
                      >
                        {c}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <div className="portal-shell-run">
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => void run()}
                  isDisabled={busy || status !== 'ready' || !input.trim()}
                  aria-label="Run command (Enter)"
                >
                  Run
                </Button>
                <Tooltip content="Save as a snippet">
                  <Button variant="plain" size="sm" aria-label="Save as snippet" icon={<StarIcon />} isDisabled={!input.trim()} onClick={() => setSaveName('')} />
                </Tooltip>
              </div>
            </div>
            <div ref={endRef} />
          </div>
          <footer className="portal-shell-hints" aria-hidden>
            <span>
              <kbd>Enter</kbd> run
            </span>
            <span>
              <kbd>Shift</kbd>+<kbd>Enter</kbd> new line
            </span>
            <span>
              <kbd>Tab</kbd> complete
            </span>
            <span>
              <kbd>↑</kbd>
              <kbd>↓</kbd> history
            </span>
            <span>
              <kbd>Ctrl</kbd>+<kbd>C</kbd> interrupt
            </span>
          </footer>
        </section>
        {panel && (
          <aside className="portal-shell-panel" aria-label="Shell helpers">
            <Tabs activeKey={panelTab} onSelect={(_e, k) => setPanelTab(k)} isFilled mountOnEnter aria-label="Shell helpers">
              <Tab eventKey="snippets" title={<TabTitleText>Snippets</TabTitleText>}>
                <div className="portal-shell-panel-body">
                  {saved.length > 0 && (
                    <div className="portal-shell-snippets">
                      <div className="portal-shell-panel-heading">My snippets</div>
                      {saved.map((s) => (
                        <div key={s.code} className="portal-shell-saved">
                          <button type="button" className="portal-shell-snippet" onClick={() => insert(s.code)} title={s.code}>
                            <span>{s.name}</span>
                            <code>{s.code.split('\n')[0]}</code>
                          </button>
                          <Button variant="plain" size="sm" aria-label={`Delete snippet ${s.name}`} icon={<TrashIcon />} onClick={() => removeSnippet(s.code)} />
                        </div>
                      ))}
                    </div>
                  )}
                  {SNIPPETS.map((g) => (
                    <div key={g.group} className="portal-shell-snippets">
                      <div className="portal-shell-panel-heading">{g.group}</div>
                      {g.items.map((s) => (
                        <button key={s.label} type="button" className="portal-shell-snippet" onClick={() => insert(s.code, s.select)} title={s.code}>
                          <span>{s.label}</span>
                          <code>{s.code.split('\n')[0]}</code>
                        </button>
                      ))}
                    </div>
                  ))}
                </div>
              </Tab>
              <Tab eventKey="history" title={<TabTitleText>History</TabTitleText>}>
                <div className="portal-shell-panel-body">
                  {history.length === 0 ? (
                    <div className="portal-shell-empty">
                      <HistoryIcon aria-hidden /> Commands you run appear here. History is kept only in this tab.
                    </div>
                  ) : (
                    <>
                      <SearchInput aria-label="Search history" placeholder="Search history" value={historyFilter} onChange={(_e, v) => setHistoryFilter(v)} onClear={() => setHistoryFilter('')} className="pf-v6-u-mb-sm" />
                      {[...history]
                        .reverse()
                        .filter((h) => !historyFilter || h.toLowerCase().includes(historyFilter.toLowerCase()))
                        .map((h, i) => (
                          <div key={`${i}-${h}`} className="portal-shell-saved">
                            <button type="button" className="portal-shell-snippet portal-shell-history" onClick={() => insert(h)} title="Insert into the prompt">
                              <code>
                                <Highlighted code={h} />
                              </code>
                            </button>
                            <Button
                              variant="plain"
                              size="sm"
                              aria-label="Save to my snippets"
                              icon={saved.some((s) => s.code === h) ? <StarIcon className="portal-status-warning" /> : <OutlinedStarIcon />}
                              onClick={() => (saved.some((s) => s.code === h) ? removeSnippet(h) : saveSnippet(h.slice(0, 40), h))}
                            />
                          </div>
                        ))}
                    </>
                  )}
                </div>
              </Tab>
              <Tab eventKey="keys" title={<TabTitleText>Keys</TabTitleText>}>
                <div className="portal-shell-panel-body">
                  <table className="portal-shell-keys">
                    <tbody>
                      {SHORTCUTS.map(([k, d]) => (
                        <tr key={k}>
                          <td>
                            <kbd>{k}</kbd>
                          </td>
                          <td>{d}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Tab>
            </Tabs>
          </aside>
        )}
      </div>
      {confirmReq && (
        <ShellConfirm
          req={confirmReq.req}
          onDone={(d) => {
            confirmReq.resolve(d);
            setConfirmReq(null);
          }}
        />
      )}
    </PageSection>
  );
}

function ShellConfirm({ req, onDone }: { req: ConfirmRequest; onDone: (d: ConfirmDecision) => void }) {
  const [typed, setTyped] = useState('');
  const [remember, setRemember] = useState(false);
  const ready = !req.typeToConfirm || typed === req.typeToConfirm;
  return (
    <Modal variant={ModalVariant.small} isOpen onClose={() => onDone({ confirmed: false })} aria-labelledby="shell-confirm-title">
      <ModalHeader title={req.title} labelId="shell-confirm-title" titleIconVariant="warning" />
      <ModalBody>
        <Content component="p">{req.summary}</Content>
        <Content component="small">Requested by a command running in the shell.</Content>
        {req.typeToConfirm && (
          <Form onSubmit={(e) => { e.preventDefault(); if (ready) onDone({ confirmed: true }); }} className="pf-v6-u-mt-md">
            <FormGroup label={`Type "${req.typeToConfirm}" to confirm`} fieldId="shell-confirm-input">
              <TextInput id="shell-confirm-input" value={typed} onChange={(_e, v) => setTyped(v)} autoComplete="off" autoFocus />
            </FormGroup>
          </Form>
        )}
        {req.allowRemember && (
          <Checkbox
            id="shell-confirm-remember"
            className="pf-v6-u-mt-md"
            label={`Don't ask again for ${req.op} in this shell session`}
            isChecked={remember}
            onChange={(_e, v) => setRemember(v)}
          />
        )}
      </ModalBody>
      <ModalFooter>
        <Button variant="danger" isDisabled={!ready} onClick={() => onDone({ confirmed: true, remember })}>
          Run {req.op}
        </Button>
        <Button variant="link" onClick={() => onDone({ confirmed: false })}>
          Cancel
        </Button>
      </ModalFooter>
    </Modal>
  );
}
