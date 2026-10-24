import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { LoginPage } from './LoginPage';
import { OperationsPage } from './OperationsPage';
import { EntryResult, ExplainSummary, resultDocuments } from '../shell/ResultTools';
import type { Me } from '../api/types';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
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
    ssoLogoutURL: '', environment: 'test', build: { version: 'v', commit: 'abcdef0' },
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
    const btn = await screen.findByText('Connect with Corporate IdP (MongoDB OIDC)');
    expect(btn.closest('a')?.getAttribute('href')).toBe('/oauth/mongodb/ent/start?return=%2F');
    await waitFor(() => expect(screen.queryByLabelText('MongoDB login')).toBeNull());
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
