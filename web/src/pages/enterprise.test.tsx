import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { LoginPage } from './LoginPage';
import { browser } from '../lib/nav';
import { OperationsPage } from './OperationsPage';
import { CachesPage } from './CachesPage';
import { AdvisorPage } from './AdvisorPage';
import { EntryResult, ExplainSummary, resultDocuments } from '../shell/ResultTools';
import type { Me } from '../api/types';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const json = (v: unknown) => new Response(JSON.stringify(v), { headers: { 'Content-Type': 'application/json' } });

function wrap(ui: ReactNode, fetchImpl: (url: string, init?: RequestInit) => Response) {
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => fetchImpl(String(url), init)));
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/login']}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

function me(over: Partial<Me['auth']> = {}): Me {
  return {
    authenticated: false, user: '', source: '', sso: false, groups: [], roles: [], permissions: {}, csrfToken: 't', hasSession: false,
    ssoLogoutURL: '', environment: 'test',
    auth: { openshift: { state: 'disabled' }, openshiftURL: '/oauth/start', header: false, dev: false, requireSSO: false, mongodbLogin: true, ...over },
  };
}

const oidcProfile = {
  name: 'ent', displayName: 'Enterprise', defaultAuthSource: 'admin', authMechanisms: ['MONGODB-OIDC'], tlsMode: 'enabled',
  clientCertificate: false, plaintextWarning: false, health: { state: 'online' },
  oidc: { displayName: 'Corporate IdP', issuer: 'https://idp.example.com', url: '/oauth/mongodb/ent/start' },
};

describe('login with OpenID Connect', () => {
  it('offers available providers and explains unavailable ones', () => {
    wrap(
      <LoginPage
        me={me({
          oidc: [
            { name: 'corp', displayName: 'Corporate SSO', state: 'available', url: '/oauth/oidc/corp/start' },
            { name: 'kc', displayName: 'Keycloak', state: 'unavailable', reason: 'not reachable', url: '/oauth/oidc/kc/start' },
          ],
        })}
      />,
      () => json({ profiles: [] }),
    );
    const btn = screen.getByText('Sign in with Corporate SSO').closest('a');
    expect(btn?.getAttribute('href')).toBe('/oauth/oidc/corp/start?return=%2F');
    expect(screen.getByText(/Keycloak is not available right now \(not reachable\)/)).toBeTruthy();
    // MongoDB-only login stays one click away.
    expect(screen.getByText('Sign in with MongoDB credentials only')).toBeTruthy();
  });

  it('connects an OIDC-only profile without a password form', async () => {
    wrap(<LoginPage me={me()} />, () => json({ profiles: [oidcProfile] }));
    const btn = await screen.findByText('Connect with Corporate IdP');
    expect(btn.closest('a')?.getAttribute('href')).toBe('/oauth/mongodb/ent/start?return=%2F');
    await waitFor(() => expect(screen.queryByLabelText('MongoDB login')).toBeNull());
    // No build, image or commit details on the sign-in page.
    expect(document.body.textContent).not.toMatch(/\b[0-9a-f]{7,40}\b|v?\d+\.\d+\.\d+/);
  });

  it('connects automatically after single sign-on, once, and can be cancelled', async () => {
    localStorage.clear();
    const assign = vi.spyOn(browser, 'assign').mockImplementation(() => {});
    const sso: Me = { ...me(), authenticated: true, sso: true, user: 'dana', source: 'openshift' };
    const auto = { ...oidcProfile, oidc: { ...oidcProfile.oidc, autoConnect: true } };
    wrap(<LoginPage me={sso} />, () => json({ profiles: [auto] }));
    expect(await screen.findByText('Connecting to Enterprise')).toBeTruthy();
    expect(screen.getByText('Portal sign-in')).toBeTruthy();
    await waitFor(() => expect(assign).toHaveBeenCalledWith('/oauth/mongodb/ent/start?return=%2F&silent=1'), { timeout: 3000 });
    cleanup();

    // A second visit within the retry window does not redirect again.
    assign.mockClear();
    wrap(<LoginPage me={sso} />, () => json({ profiles: [auto] }));
    expect(await screen.findByText('Connect with Corporate IdP')).toBeTruthy();
    expect(assign).not.toHaveBeenCalled();
    cleanup();

    // Cancelling shows the other ways to connect.
    localStorage.clear();
    wrap(<LoginPage me={sso} />, () => json({ profiles: [auto] }));
    fireEvent.click(await screen.findByText('Choose another way to connect'));
    expect(await screen.findByText('Connect with Corporate IdP')).toBeTruthy();
    await new Promise((r) => setTimeout(r, 900));
    expect(assign).not.toHaveBeenCalled();
  });

  it('does not connect automatically after a failure', async () => {
    localStorage.clear();
    const assign = vi.spyOn(browser, 'assign').mockImplementation(() => {});
    const sso: Me = { ...me(), authenticated: true, sso: true, user: 'dana', source: 'openshift' };
    vi.stubGlobal('fetch', vi.fn(async () => json({ profiles: [{ ...oidcProfile, oidc: { ...oidcProfile.oidc, autoConnect: true } }] })));
    render(
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter initialEntries={['/login?mongo=token_audience_mismatch&profile=ent']}>
          <LoginPage me={sso} />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(await screen.findByText(/issued for a different audience/)).toBeTruthy();
    expect(screen.getByText('Diagnose connection')).toBeTruthy();
    await new Promise((r) => setTimeout(r, 900));
    expect(assign).not.toHaveBeenCalled();
  });

  it('explains MONGODB-OIDC failures', () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ profiles: [] })));
    const qc = new QueryClient();
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={['/login?mongo=mongo_rejected&profile=ent']}>
          <LoginPage me={me()} />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(screen.getByText(/MongoDB rejected your OIDC identity/)).toBeTruthy();
  });
});

describe('operations', () => {
  it('ends an operation only after the id is typed', async () => {
    const calls: { url: string; body?: string }[] = [];
    wrap(<OperationsPage />, (url, init) => {
      calls.push({ url, body: init?.body as string | undefined });
      if (url.includes('/operations/kill')) return json({ killed: true, note: 'killOp marks the operation for termination.' });
      return json({
        operations: [{ opid: 4711, type: 'op', op: 'query', ns: 'app.orders', active: true, secsRunning: 42, client: '10.0.0.9:5000', appName: 'batch',
          user: 'svc', desc: 'conn9', waitingForLock: false, killPending: false, slow: true, portal: false, internal: false }],
        total: 1, offset: 0, limit: 50, allUsers: true, slowSeconds: 5, canKill: true,
      });
    });
    fireEvent.click(await screen.findByText('End…'));
    const confirm = screen.getByText('End operation 4711').closest('button')!;
    expect(confirm.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText('Operation id to confirm'), { target: { value: '4711' } });
    expect(confirm.disabled).toBe(false);
    fireEvent.click(confirm);
    await screen.findByText(/marks the operation for termination/);
    const kill = calls.find((c) => c.url.includes('/operations/kill'));
    expect(JSON.parse(kill!.body!)).toEqual({ opid: 4711, confirm: '4711' });
  });
});

describe('shell result tools', () => {
  const cursor = { type: 'Cursor', value: { documents: [{ _id: 1, name: 'a', n: { $numberInt: '3' } }, { _id: 2, name: 'b, "c"' }], cursorHasMore: false } };

  it('finds documents and renders a table', () => {
    expect(resultDocuments([cursor])?.length).toBe(2);
    expect(resultDocuments([{ type: null, value: 'text' }])).toBeNull();
    render(<EntryResult outputs={[cursor]} />);
    fireEvent.click(screen.getByText('Table'));
    expect(screen.getByText('name')).toBeTruthy();
    expect(screen.getByText('b, "c"')).toBeTruthy();
  });

  it('summarizes explain output', () => {
    render(
      <ExplainSummary
        explain={{
          queryPlanner: { winningPlan: { stage: 'FETCH', inputStage: { stage: 'COLLSCAN' } } },
          executionStats: { nReturned: 2, totalKeysExamined: 0, totalDocsExamined: 1000, executionTimeMillis: 12 },
        }}
      />,
    );
    expect(screen.getByText(/COLLSCAN → FETCH/)).toBeTruthy();
    expect(screen.getByText('collection scan')).toBeTruthy();
    expect(screen.getByText(/500× more documents examined than returned/)).toBeTruthy();
  });
});

describe('caches', () => {
  it('invalidates selected caches only after typed confirmation', async () => {
    const calls: { url: string; body?: string }[] = [];
    wrap(<CachesPage />, (url, init) => {
      calls.push({ url, body: init?.body as string | undefined });
      if (url.includes('/invalidate')) return json({ results: [{ name: 'rbac-policy', ok: true }], scope: 'all', note: 'Applied here; other replicas apply it within 10s.' });
      return json({
        pod: 'portal-a', shared: true, canInvalidate: true,
        caches: [
          { name: 'identities', title: 'Signed-in identities and groups', description: 'd', entries: 2 },
          { name: 'rbac-policy', title: 'RBAC policy', description: 'd', entries: 1, refreshedAt: '2026-01-01T00:00:00Z' },
        ],
        recent: [{ id: '1', caches: ['identities'], requestedBy: 'pat', origin: 'portal-b', at: '2026-01-01T00:00:00Z', applied: [{ pod: 'portal-b', at: '2026-01-01T00:00:00Z' }] }],
      });
    });
    await screen.findByText('RBAC policy');
    expect(screen.getByText('portal-b')).toBeTruthy();
    fireEvent.click(screen.getAllByRole('checkbox')[1]);
    fireEvent.click(screen.getByText(/Invalidate 1 selected/));
    const invalidate = await screen.findByRole('button', { name: 'Invalidate' });
    expect((invalidate as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText(/to confirm/), { target: { value: 'invalidate' } });
    fireEvent.click(invalidate);
    await screen.findByText('Caches invalidated');
    const post = calls.find((c) => c.url.includes('/invalidate'));
    expect(JSON.parse(post!.body!)).toEqual({ caches: ['rbac-policy'], scope: 'all', confirm: 'invalidate' });
  });
});

describe('performance advisor', () => {
  it('runs only on request and shows findings with suggestions', async () => {
    const calls: string[] = [];
    wrap(<AdvisorPage />, (url) => {
      calls.push(url);
      if (url.includes('/databases')) return json({ databases: [{ name: 'app', sizeOnDisk: 1, empty: false }, { name: 'admin', sizeOnDisk: 1, empty: false }] });
      return json({
        profile: 'prod', generatedAt: '2026-10-25T10:00:00Z', duration: '1.2s', truncated: false,
        scanned: { databases: 1, collections: 3, queries: 12 },
        sources: [{ name: 'Profiler (system.profile)', state: 'off', detail: 'profiling is off' }],
        findings: [
          { severity: 'critical', kind: 'missing_index', namespace: 'app.orders', title: 'Query scans the whole collection', detail: 'Each run reads about 2000000 documents to return 3.',
            evidence: { occurrences: 4, query: '{"customer":"?"}' }, suggestion: 'db.getSiblingDB("app").getCollection("orders").createIndex({ "customer": 1 })' },
          { severity: 'info', kind: 'no_constraints', namespace: 'app', title: '2 collections without constraints', detail: 'd', evidence: { collections: ['a', 'b'], total: 2 } },
        ],
      });
    });
    await screen.findByText('Analyze this deployment');
    expect(calls.some((u) => u.includes('/advisor'))).toBe(false);
    expect(screen.queryByRole('option', { name: 'admin' })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Analyze' }));
    await screen.findByText('Query scans the whole collection');
    expect(screen.getByText('{"customer":"?"}')).toBeTruthy();
    expect(screen.getByText('db.getSiblingDB("app").getCollection("orders").createIndex({ "customer": 1 })')).toBeTruthy();
    expect(screen.getByText(/never runs commands/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Info (1)' }));
    expect(screen.queryByText('Query scans the whole collection')).toBeNull();
    expect(screen.getByText('2 collections without constraints')).toBeTruthy();
  });
});
