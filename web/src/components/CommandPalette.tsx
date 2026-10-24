import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useNavigate, useParams } from 'react-router';
import { Label, Modal, ModalBody, ModalVariant, SearchInput } from '@patternfly/react-core';
import {
  ArrowRightIcon,
  BoltIcon,
  ClipboardCheckIcon,
  CubeIcon,
  DatabaseIcon,
  HistoryIcon,
  KeyboardIcon,
  ListIcon,
  LockIcon,
  ServerIcon,
  SignOutAltIcon,
  TachometerAltIcon,
  TerminalIcon,
} from '@patternfly/react-icons';
import { useCollections, useDatabases } from '../api/hooks';
import { recentItems } from '../lib/recent';

export interface PaletteItem {
  id: string;
  label: string;
  hint?: string;
  group: string;
  icon: ReactNode;
  run: () => void;
  keywords?: string;
}

/**
 * Ranks text against a query: exact prefix > substring > subsequence.
 * Returns -1 when the text does not match. Exported for tests.
 */
export function fuzzyScore(query: string, text: string): number {
  const q = query.trim().toLowerCase();
  if (!q) return 1;
  const t = text.toLowerCase();
  if (t.startsWith(q)) return 1000 - t.length;
  const i = t.indexOf(q);
  if (i >= 0) return 500 - i;
  let ti = 0;
  let gaps = 0;
  for (const ch of q) {
    const found = t.indexOf(ch, ti);
    if (found < 0) return -1;
    gaps += found - ti;
    ti = found + 1;
  }
  return Math.max(1, 200 - gaps);
}

const SEARCH_LABEL = 'Search databases, collections, pages and actions';
const SEARCH_SELECTOR = `input[aria-label="${SEARCH_LABEL}"]`;

export type PaletteAction = 'theme' | 'shortcuts' | 'disconnect' | 'signout';

interface PaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onAction: (a: PaletteAction) => void;
}

/** Mounted only while open, so every opening starts with a fresh search. */
export function CommandPalette(props: PaletteProps) {
  return props.isOpen ? <PaletteDialog {...props} /> : null;
}

function PaletteDialog({ isOpen, onClose, onAction }: PaletteProps) {
  const navigate = useNavigate();
  const { db: activeDb } = useParams();
  const [query, setQuery] = useState('');
  const [cursor, setCursor] = useState(0);
  const listRef = useRef<HTMLUListElement>(null);
  const dbs = useDatabases();
  // "db.coll" searches the collections of db; otherwise the current database.
  const dotted = query.includes('.') ? query.slice(0, query.indexOf('.')) : undefined;
  const collDb = dotted && dbs.data?.databases.some((d) => d.name === dotted) ? dotted : activeDb;
  const colls = useCollections(isOpen ? collDb : undefined);

  const items = useMemo<PaletteItem[]>(() => {
    const go = (path: string) => () => {
      onClose();
      navigate(path);
    };
    const act = (a: PaletteAction) => () => {
      onClose();
      onAction(a);
    };
    const nsPath = (db: string, coll?: string) =>
      coll ? `/db/${encodeURIComponent(db)}/${encodeURIComponent(coll)}` : `/db/${encodeURIComponent(db)}`;
    const out: PaletteItem[] = [];
    if (!query.trim()) {
      for (const r of recentItems()) {
        out.push({ id: `recent:${r.db}/${r.coll ?? ''}`, label: r.coll ? `${r.db}.${r.coll}` : r.db, group: 'Recent', icon: <HistoryIcon />, run: go(nsPath(r.db, r.coll)) });
      }
    }
    for (const d of dbs.data?.databases ?? []) {
      out.push({ id: `db:${d.name}`, label: d.name, hint: 'database', group: 'Databases', icon: <DatabaseIcon />, run: go(nsPath(d.name)) });
    }
    if (collDb) {
      for (const c of colls.data?.collections ?? []) {
        out.push({
          id: `coll:${collDb}/${c.name}`,
          label: `${collDb}.${c.name}`,
          hint: c.type === 'view' ? 'view' : 'collection',
          group: `Collections in ${collDb}`,
          icon: <CubeIcon />,
          run: go(nsPath(collDb, c.name)),
        });
      }
    }
    const pages: [string, string, ReactNode, string?][] = [
      ['Dashboard', '/', <TachometerAltIcon key="i" />, 'home overview health'],
      ['Databases', '/databases', <ListIcon key="i" />],
      ['Import & export', '/transfer', <ListIcon key="i" />, 'import export csv json bson upload download'],
      ['Operations', '/operations', <ServerIcon key="i" />, 'currentop killop running slow idle connections'],
      ['Sessions administration', '/admin/sessions', <LockIcon key="i" />, 'revoke sessions users'],
      ['Settings', '/settings', <ClipboardCheckIcon key="i" />, 'configuration oidc profiles'],
      ['Shell', activeDb ? `/shell?db=${encodeURIComponent(activeDb)}` : '/shell', <TerminalIcon key="i" />, 'mongosh console'],
      ['Monitoring', '/monitoring', <ServerIcon key="i" />, 'server replica set primary secondary connections idle size metrics'],
      ['Session & security', '/session', <LockIcon key="i" />, 'sessions logout'],
      ['My permissions', '/permissions', <ClipboardCheckIcon key="i" />, 'rbac roles access policy'],
      ['System status', '/status', <TachometerAltIcon key="i" />, 'health openshift sso integrations'],
      ['Audit activity', '/audit', <HistoryIcon key="i" />, 'log events'],
    ];
    for (const [label, path, icon, keywords] of pages) {
      out.push({ id: `page:${path}`, label, group: 'Go to', icon, run: go(path), keywords });
    }
    out.push(
      { id: 'act:theme', label: 'Toggle dark / light theme', group: 'Actions', icon: <BoltIcon />, run: act('theme'), keywords: 'appearance' },
      { id: 'act:shortcuts', label: 'Keyboard shortcuts', group: 'Actions', icon: <KeyboardIcon />, run: act('shortcuts'), keywords: 'help keys' },
      { id: 'act:disconnect', label: 'Disconnect from MongoDB', group: 'Actions', icon: <SignOutAltIcon />, run: act('disconnect'), keywords: 'logout' },
      { id: 'act:signout', label: 'Sign out', group: 'Actions', icon: <SignOutAltIcon />, run: act('signout'), keywords: 'logout openshift sso' },
    );
    return out
      .map((it) => ({ it, s: Math.max(fuzzyScore(query, it.label), it.keywords ? fuzzyScore(query, it.keywords) - 100 : -1) }))
      .filter((x) => x.s >= 0)
      .sort((a, b) => (query.trim() ? b.s - a.s : 0))
      .slice(0, 60)
      .map((x) => x.it);
  }, [query, dbs.data, colls.data, collDb, activeDb, navigate, onAction, onClose]);

  const active = Math.min(cursor, Math.max(0, items.length - 1));

  useEffect(() => {
    listRef.current?.querySelector('[aria-selected="true"]')?.scrollIntoView?.({ block: 'nearest' });
  }, [active]);

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setCursor(Math.min(items.length - 1, active + 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setCursor(Math.max(0, active - 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      items[active]?.run();
    }
  };

  return (
    <Modal
      variant={ModalVariant.medium}
      isOpen={isOpen}
      onClose={onClose}
      aria-label="Command palette"
      position="top"
      className="portal-palette"
      // Focus the search box (not the close button) so typing searches immediately.
      elementToFocus={SEARCH_SELECTOR}
    >
      <ModalBody>
        <div onKeyDown={onKeyDown}>
          <SearchInput
            aria-label={SEARCH_LABEL}
            placeholder="Search databases, collections (db.coll), pages and actions"
            value={query}
            onChange={(_e, v) => {
              setQuery(v);
              setCursor(0);
            }}
            onClear={() => setQuery('')}
            autoFocus
          />
          <ul className="portal-palette-list" role="listbox" aria-label="Results" ref={listRef}>
            {items.map((it, i) => {
              const header = i === 0 || items[i - 1].group !== it.group ? it.group : undefined;
              return (
                <li key={it.id} role="presentation">
                  {header && <div className="portal-palette-group">{header}</div>}
                  <div
                    role="option"
                    aria-selected={i === active}
                    className={`portal-palette-item${i === active ? ' is-active' : ''}`}
                    onMouseEnter={() => setCursor(i)}
                    onClick={it.run}
                  >
                    <span className="portal-palette-icon">{it.icon}</span>
                    <span className="portal-palette-label">{it.label}</span>
                    {it.hint && (
                      <Label isCompact variant="outline">
                        {it.hint}
                      </Label>
                    )}
                    {i === active && <ArrowRightIcon className="portal-palette-enter" />}
                  </div>
                </li>
              );
            })}
            {items.length === 0 && <li className="portal-palette-empty">No matches</li>}
          </ul>
          <div className="portal-palette-footer">
            <kbd>↑</kbd> <kbd>↓</kbd> to move · <kbd>Enter</kbd> to open · <kbd>Esc</kbd> to close
          </div>
        </div>
      </ModalBody>
    </Modal>
  );
}
