import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { NavLink, Outlet, useNavigate, useParams } from 'react-router';
import {
  Button,
  Divider,
  Dropdown,
  DropdownGroup,
  DropdownItem,
  DropdownList,
  Label,
  Masthead,
  MastheadBrand,
  MastheadContent,
  MastheadLogo,
  MastheadMain,
  MastheadToggle,
  MenuToggle,
  Modal,
  ModalBody,
  ModalHeader,
  ModalVariant,
  Nav,
  NavGroup,
  NavItem,
  NavList,
  Page,
  PageSidebar,
  PageSidebarBody,
  PageToggleButton,
  SearchInput,
  Spinner,
  Toolbar,
  ToolbarContent,
  ToolbarGroup,
  ToolbarItem,
  Tooltip,
} from '@patternfly/react-core';
import {
  BarsIcon,
  ClipboardCheckIcon,
  CogIcon,
  CubeIcon,
  CubesIcon,
  DatabaseIcon,
  ExchangeAltIcon,
  HistoryIcon,
  HomeIcon,
  ListIcon,
  UsersIcon,
  KeyboardIcon,
  LayerGroupIcon,
  LightbulbIcon,
  LockIcon,
  MoonIcon,
  SearchIcon,
  ServerIcon,
  SunIcon,
  SyncAltIcon,
  TachometerAltIcon,
  TerminalIcon,
  UnlockIcon,
} from '@patternfly/react-icons';
import type { Me } from '../api/types';
import { useCollections, useDatabases, useLogout, useSession, useSignOut } from '../api/hooks';
import { applyTheme, currentTheme, type Theme } from '../lib/theme';
import { rememberRecent } from '../lib/recent';
import { ConnectionPanel } from './ConnectionPanel';
import { CommandPalette, type PaletteAction } from './CommandPalette';
import { IdentityLabel, SourceIcon, sourceDescription } from './Indicators';
import { RolesLabel } from './Permission';

const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform);
const modKey = isMac ? '⌘' : 'Ctrl';

const shortcuts: [string, string][] = [
  [`${modKey} K`, 'Open the command palette'],
  ['/', 'Open the command palette'],
  ['g then d', 'Go to databases'],
  ['g then s', 'Go to the shell'],
  ['g then p', 'Go to my permissions'],
  ['g then t', 'Go to system status'],
  ['g then a', 'Go to audit activity'],
  ['?', 'Show keyboard shortcuts'],
  ['Esc', 'Close dialogs'],
];

function typingTarget(t: EventTarget | null): boolean {
  const el = t as HTMLElement | null;
  if (!el) return false;
  return el.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName) || !!el.closest?.('.portal-shell, .cm-editor');
}

export function AppLayout({ me }: { me: Me }) {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [theme, setTheme] = useState<Theme>(currentTheme());
  const [userOpen, setUserOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [connOpen, setConnOpen] = useState(false);
  const session = useSession();
  const logout = useLogout();
  const signOut = useSignOut();
  const navigate = useNavigate();
  const { db, coll } = useParams();
  const chord = useRef<number>(0);

  useEffect(() => {
    if (db) rememberRecent({ db, coll });
  }, [db, coll]);

  const toggleTheme = useCallback(() => {
    const t = currentTheme() === 'dark' ? 'light' : 'dark';
    applyTheme(t);
    setTheme(t);
  }, []);

  const doLogout = useCallback(async () => {
    setUserOpen(false);
    try {
      await logout.mutateAsync();
    } finally {
      navigate('/login?reason=logout', { replace: true });
    }
  }, [logout, navigate]);

  const doSignOut = useCallback(async () => {
    setUserOpen(false);
    let idpLogout = '';
    try {
      idpLogout = (await signOut.mutateAsync()).ssoLogoutURL;
    } catch {
      // best effort
    }
    if (idpLogout) window.location.assign(idpLogout);
    else navigate('/login?reason=signedout', { replace: true });
  }, [signOut, navigate]);

  const onPaletteAction = useCallback(
    (a: PaletteAction) => {
      if (a === 'theme') toggleTheme();
      if (a === 'shortcuts') setShortcutsOpen(true);
      if (a === 'disconnect') void doLogout();
      if (a === 'signout') void doSignOut();
    },
    [toggleTheme, doLogout, doSignOut],
  );
  const closePalette = useCallback(() => setPaletteOpen(false), []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen((o) => !o);
        return;
      }
      if (e.metaKey || e.ctrlKey || e.altKey || typingTarget(e.target)) return;
      if (e.key === '/') {
        e.preventDefault();
        setPaletteOpen(true);
      } else if (e.key === '?') {
        setShortcutsOpen(true);
      } else if (e.key === 'g') {
        chord.current = Date.now();
      } else if (Date.now() - chord.current < 1200) {
        const dest: Record<string, string> = { d: '/', s: db ? `/shell?db=${encodeURIComponent(db)}` : '/shell', p: '/permissions', t: '/status', a: '/audit' };
        if (dest[e.key]) {
          e.preventDefault();
          navigate(dest[e.key]);
        }
        chord.current = 0;
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [navigate, db]);

  const s = session.data;
  const roles = s?.portalRoles ?? me.roles;
  const identity = s?.identity ?? { user: me.user, source: me.source, groups: me.groups };

  const masthead = (
    <Masthead>
      <MastheadMain>
        <MastheadToggle>
          <PageToggleButton variant="plain" aria-label="Toggle navigation" isSidebarOpen={sidebarOpen} onSidebarToggle={() => setSidebarOpen((o) => !o)}>
            <BarsIcon />
          </PageToggleButton>
        </MastheadToggle>
        <MastheadBrand>
          <MastheadLogo component={(p) => <NavLink to="/" {...p} />}>
            <span className="portal-brand">
              <span className="portal-logo-mark" aria-hidden>
                <DatabaseIcon />
              </span>
              MongoDB Portal
            </span>
          </MastheadLogo>
        </MastheadBrand>
      </MastheadMain>
      <MastheadContent>
        <Toolbar isFullHeight isStatic>
          <ToolbarContent>
            <ToolbarItem visibility={{ default: 'hidden', lg: 'visible' }}>
              <Button variant="secondary" className="portal-palette-trigger" icon={<SearchIcon />} onClick={() => setPaletteOpen(true)} aria-label="Open command palette">
                Jump to… <kbd>{modKey} K</kbd>
              </Button>
            </ToolbarItem>
            <ToolbarGroup align={{ default: 'alignEnd' }} gap={{ default: 'gapMd' }}>
              {me.environment && (
                <ToolbarItem visibility={{ default: 'hidden', md: 'visible' }}>
                  <Label color="grey">{me.environment}</Label>
                </ToolbarItem>
              )}
              {s && (
                <ToolbarItem visibility={{ default: 'hidden', md: 'visible' }}>
                  <Tooltip content={s.tls ? 'Connection to MongoDB is encrypted with TLS' : 'Connection to MongoDB is NOT encrypted'}>
                    <Label color={s.tls ? 'green' : 'red'} icon={s.tls ? <LockIcon /> : <UnlockIcon />}>
                      {s.profileInfo?.displayName ?? s.profile}
                    </Label>
                  </Tooltip>
                </ToolbarItem>
              )}
              <ToolbarItem>
                <RolesLabel roles={roles} compact />
              </ToolbarItem>
              <ToolbarItem>
                <Tooltip content="Refresh &amp; connection">
                  <Button variant="plain" aria-label="Refresh and connection" icon={<SyncAltIcon />} onClick={() => setConnOpen(true)} />
                </Tooltip>
              </ToolbarItem>
              <ToolbarItem>
                <Button
                  variant="plain"
                  aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
                  onClick={toggleTheme}
                  icon={theme === 'dark' ? <SunIcon /> : <MoonIcon />}
                />
              </ToolbarItem>
              <ToolbarItem>
                <Dropdown
                  isOpen={userOpen}
                  onOpenChange={setUserOpen}
                  popperProps={{ position: 'right' }}
                  toggle={(ref) => (
                    <MenuToggle ref={ref} variant="plainText" icon={<SourceIcon source={identity.source} />} onClick={() => setUserOpen((o) => !o)} isExpanded={userOpen}>
                      {s ? `${s.mongoUser}${identity.source !== 'mongodb' ? ` (${identity.user})` : ''}` : identity.user}
                    </MenuToggle>
                  )}
                >
                  <DropdownGroup label={sourceDescription(identity.source)}>
                    <DropdownList>
                      <DropdownItem key="id" isDisabled description={(identity.groups ?? []).slice(0, 4).join(', ') || undefined}>
                        <IdentityLabel user={identity.user} source={identity.source} />
                      </DropdownItem>
                    </DropdownList>
                  </DropdownGroup>
                  <Divider component="li" />
                  <DropdownList>
                    <DropdownItem key="perm" icon={<ClipboardCheckIcon />} onClick={() => { setUserOpen(false); navigate('/permissions'); }}>
                      My permissions
                    </DropdownItem>
                    <DropdownItem key="session" icon={<LockIcon />} onClick={() => { setUserOpen(false); navigate('/session'); }}>
                      Session &amp; security
                    </DropdownItem>
                    <DropdownItem key="status" icon={<TachometerAltIcon />} onClick={() => { setUserOpen(false); navigate('/status'); }}>
                      System status
                    </DropdownItem>
                    <DropdownItem key="conn" icon={<SyncAltIcon />} onClick={() => { setUserOpen(false); setConnOpen(true); }}>
                      Refresh &amp; connection
                    </DropdownItem>
                    <DropdownItem key="keys" icon={<KeyboardIcon />} onClick={() => { setUserOpen(false); setShortcutsOpen(true); }}>
                      Keyboard shortcuts
                    </DropdownItem>
                  </DropdownList>
                  <Divider component="li" />
                  <DropdownList>
                    <DropdownItem key="logout" onClick={() => void doLogout()}>
                      Disconnect from MongoDB
                    </DropdownItem>
                    <DropdownItem key="signout" onClick={() => void doSignOut()} description={identity.source === 'openshift' ? 'Ends the OpenShift sign-in of this browser too' : undefined}>
                      Sign out
                    </DropdownItem>
                  </DropdownList>
                </Dropdown>
              </ToolbarItem>
            </ToolbarGroup>
          </ToolbarContent>
        </Toolbar>
      </MastheadContent>
    </Masthead>
  );

  const sidebar = (
    <PageSidebar isSidebarOpen={sidebarOpen}>
      <PageSidebarBody>
        <Sidebar me={me} />
      </PageSidebarBody>
    </PageSidebar>
  );

  return (
    <Page masthead={masthead} sidebar={sidebar} isContentFilled>
      {s && !s.tls && (
        <div className="portal-banner" role="alert">
          <UnlockIcon /> MongoDB traffic for this connection profile is not encrypted. Credentials and data travel in plaintext between the portal and MongoDB.
        </div>
      )}
      <Outlet />
      <ConnectionPanel isOpen={connOpen} onClose={() => setConnOpen(false)} session={s} />
      <CommandPalette isOpen={paletteOpen} onClose={closePalette} onAction={onPaletteAction} />
      <Modal variant={ModalVariant.small} isOpen={shortcutsOpen} onClose={() => setShortcutsOpen(false)} aria-labelledby="shortcuts-title">
        <ModalHeader title="Keyboard shortcuts" labelId="shortcuts-title" />
        <ModalBody>
          <table className="portal-shortcuts">
            <tbody>
              {shortcuts.map(([k, d]) => (
                <tr key={k}>
                  <td>
                    {k.split(' ').map((part, i) => (part === 'then' ? <span key={i}> then </span> : <kbd key={i}>{part}</kbd>))}
                  </td>
                  <td>{d}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </ModalBody>
      </Modal>
    </Page>
  );
}

function Sidebar({ me }: { me: Me }) {
  const [filter, setFilter] = useState('');
  const perm = (k: string) => me.permissions[k] !== false;
  const { db: activeDb, coll: activeColl } = useParams();
  const dbs = useDatabases();
  const colls = useCollections(activeDb);
  const f = filter.trim().toLowerCase();

  const dbList = useMemo(() => (dbs.data?.databases ?? []).filter((d) => !f || d.name.toLowerCase().includes(f) || d.name === activeDb), [dbs.data, f, activeDb]);
  const collList = useMemo(() => (colls.data?.collections ?? []).filter((c) => !f || c.name.toLowerCase().includes(f)), [colls.data, f]);

  return (
    <>
      <div className="pf-v6-u-p-md">
        <SearchInput
          aria-label="Filter databases and collections"
          placeholder="Filter databases & collections"
          value={filter}
          onChange={(_e, v) => setFilter(v)}
          onClear={() => setFilter('')}
        />
      </div>
      <Nav aria-label="Database navigation">
        <NavList>
          <NavItem>
            <NavLink to="/" end><span className="portal-nav-icon"><HomeIcon /></span>
              Dashboard
            </NavLink>
          </NavItem>
          <NavItem>
            <NavLink to="/databases"><span className="portal-nav-icon"><ListIcon /></span>All databases</NavLink>
          </NavItem>
        </NavList>
        <NavGroup title="Databases">
          {dbs.isPending && <Spinner size="md" className="pf-v6-u-ml-md" aria-label="Loading databases" />}
          <NavList>
            {dbList.map((d) => (
              <NavItem key={d.name} isActive={d.name === activeDb && !activeColl}>
                <NavLink to={`/db/${encodeURIComponent(d.name)}`}><span className="portal-nav-icon"><DatabaseIcon /></span>{d.name}</NavLink>
              </NavItem>
            ))}
          </NavList>
        </NavGroup>
        {activeDb && (
          <NavGroup title={`Collections in ${activeDb}`}>
            {colls.isPending && <Spinner size="md" className="pf-v6-u-ml-md" aria-label="Loading collections" />}
            <NavList>
              {collList.map((c) => (
                <NavItem key={c.name} isActive={c.name === activeColl}>
                  <NavLink to={`/db/${encodeURIComponent(activeDb)}/${encodeURIComponent(c.name)}`}><span className="portal-nav-icon"><CubeIcon /></span>{c.name}</NavLink>
                </NavItem>
              ))}
            </NavList>
          </NavGroup>
        )}
        <Divider />
        <NavGroup title="Work">
          <NavList>
            <NavItem>
              <NavLink to={activeDb ? `/shell?db=${encodeURIComponent(activeDb)}` : '/shell'}><span className="portal-nav-icon"><TerminalIcon /></span>Shell</NavLink>
            </NavItem>
            {(perm('export:create') || perm('import:create')) && (
              <NavItem>
                <NavLink to={activeDb ? `/transfer?db=${encodeURIComponent(activeDb)}${activeColl ? `&coll=${encodeURIComponent(activeColl)}` : ''}` : '/transfer'}><span className="portal-nav-icon"><ExchangeAltIcon /></span>
                  Import &amp; export
                </NavLink>
              </NavItem>
            )}
          </NavList>
        </NavGroup>
        <NavGroup title="Operate">
          <NavList>
            {perm('monitoring:get') && (
              <NavItem>
                <NavLink to="/monitoring"><span className="portal-nav-icon"><ServerIcon /></span>Monitoring</NavLink>
              </NavItem>
            )}
            {perm('operations:get') && (
              <NavItem>
                <NavLink to="/operations"><span className="portal-nav-icon"><CubesIcon /></span>Operations</NavLink>
              </NavItem>
            )}
            {perm('monitoring:get') && (
              <NavItem>
                <NavLink to="/advisor"><span className="portal-nav-icon"><LightbulbIcon /></span>Performance advisor</NavLink>
              </NavItem>
            )}
            <NavItem>
              <NavLink to="/audit"><span className="portal-nav-icon"><HistoryIcon /></span>Audit</NavLink>
            </NavItem>
            {me.permissions['sessions:all'] && (
              <NavItem>
                <NavLink to="/admin/sessions"><span className="portal-nav-icon"><UsersIcon /></span>Sessions</NavLink>
              </NavItem>
            )}
          </NavList>
        </NavGroup>
        <NavGroup title="Security">
          <NavList>
            <NavItem>
              <NavLink to="/session"><span className="portal-nav-icon"><LockIcon /></span>My session</NavLink>
            </NavItem>
            <NavItem>
              <NavLink to="/permissions"><span className="portal-nav-icon"><ClipboardCheckIcon /></span>My permissions</NavLink>
            </NavItem>
            {me.permissions['cache:get'] && (
              <NavItem>
                <NavLink to="/admin/caches"><span className="portal-nav-icon"><LayerGroupIcon /></span>Caches</NavLink>
              </NavItem>
            )}
            {me.permissions['settings:get'] && (
              <NavItem>
                <NavLink to="/settings"><span className="portal-nav-icon"><CogIcon /></span>Settings</NavLink>
              </NavItem>
            )}
            <NavItem>
              <NavLink to="/status"><span className="portal-nav-icon"><TachometerAltIcon /></span>System status</NavLink>
            </NavItem>
          </NavList>
        </NavGroup>
      </Nav>
    </>
  );
}
