import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { DocumentView } from './DocumentView';
import { canDo, primaryRole, RolesLabel } from './Permission';
import { fuzzyScore } from './CommandPalette';
import { DocumentCard } from '../pages/collection/DocumentCard';
import { LoginPage } from '../pages/LoginPage';
import type { Access, Capabilities, Me, PortalAccess } from '../api/types';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const allCaps: Capabilities = {
  find: true, insert: true, update: true, remove: true, createIndex: true, dropIndex: true,
  createCollection: true, dropCollection: true, listCollections: true, listIndexes: true, dbStats: true, collStats: true,
};

const portal = (v: boolean): PortalAccess => ({
  find: true, insert: v, update: v, remove: v, createIndex: v, dropIndex: v, createCollection: v, dropCollection: v, dropDatabase: v,
});

describe('DocumentView', () => {
  it('renders BSON types and escapes HTML', () => {
    render(
      <DocumentView
        doc={{
          _id: { $oid: '507f1f77bcf86cd799439011' },
          price: { $numberDecimal: '9.99' },
          html: '<img src=x onerror=alert(1)>',
          nested: { a: { $date: { $numberLong: '0' } } },
        }}
      />,
    );
    expect(screen.getByText('ObjectId("507f1f77bcf86cd799439011")')).toBeTruthy();
    expect(screen.getByText('NumberDecimal("9.99")')).toBeTruthy();
    expect(screen.getByText('"<img src=x onerror=alert(1)>"')).toBeTruthy();
    expect(document.querySelector('img')).toBeNull();
    expect(screen.getByText('ISODate("1970-01-01T00:00:00.000Z")')).toBeTruthy();
  });
});

describe('permission gating (UI hints only)', () => {
  const readonly: Access = { portalWrite: false, portal: portal(false), mongo: allCaps };
  const editor: Access = { portalWrite: true, portal: portal(true), mongo: { ...allCaps, remove: false } };

  it('never offers writes the RBAC policy denies, even with MongoDB write privileges', () => {
    expect(canDo(readonly, 'insert')).toBe(false);
    expect(canDo(readonly, 'dropCollection')).toBe(false);
  });

  it('offers writes only where RBAC and MongoDB both allow them', () => {
    expect(canDo(editor, 'insert')).toBe(true);
    expect(canDo(editor, 'remove')).toBe(false);
    expect(canDo({ ...editor, portal: { ...portal(true), insert: false } }, 'insert')).toBe(false);
  });

  it('hides edit and delete buttons for read-only users', () => {
    render(<DocumentCard doc={{ _id: { $numberInt: '1' } }} id="x" access={readonly} raw={false} onEdit={() => {}} onDelete={() => {}} />);
    expect(screen.queryByLabelText('Edit document')).toBeNull();
    expect(screen.queryByLabelText('Delete document')).toBeNull();
    expect(screen.getByLabelText('Copy document JSON')).toBeTruthy();
  });

  it('labels roles', () => {
    expect(primaryRole(['role:readonly', 'role:admin'])).toBe('role:admin');
    render(<RolesLabel roles={[]} />);
    expect(screen.getByText('No access')).toBeTruthy();
  });
});

describe('command palette ranking', () => {
  it('prefers prefixes, then substrings, then subsequences', () => {
    expect(fuzzyScore('ord', 'orders')).toBeGreaterThan(fuzzyScore('ord', 'app.orders'));
    expect(fuzzyScore('ord', 'app.orders')).toBeGreaterThan(fuzzyScore('ord', 'o_r_d'));
    expect(fuzzyScore('xyz', 'orders')).toBe(-1);
    expect(fuzzyScore('', 'anything')).toBeGreaterThan(0);
  });
});

function me(over: Partial<Me> = {}): Me {
  return {
    authenticated: false, user: '', source: '', sso: false, groups: [], roles: [], permissions: {},
    csrfToken: 't', hasSession: false, ssoLogoutURL: '', environment: 'test', build: { version: 'v', commit: 'abcdef0' },
    auth: { openshift: { state: 'disabled' }, openshiftURL: '/oauth/start', header: false, dev: false, requireSSO: false, mongodbLogin: true },
    ...over,
  };
}

function renderLogin(m: Me, url = '/login') {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ profiles: [
    { name: 'p', displayName: 'Primary', defaultAuthSource: 'admin', authMechanisms: ['SCRAM-SHA-256'], tlsMode: 'enabled',
      clientCertificate: false, plaintextWarning: false, health: { state: 'online', latencyMs: 3 } },
  ] }), { headers: { 'Content-Type': 'application/json' } })));
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}>
        <LoginPage me={m} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('login page (passive SSO)', () => {
  it('offers OpenShift login when it is available, MongoDB login on request', () => {
    renderLogin(me({ auth: { ...me().auth, openshift: { state: 'available' } } }));
    const btn = screen.getByText('Log in with OpenShift').closest('a');
    expect(btn?.getAttribute('href')).toBe('/oauth/start?return=%2F');
    expect(screen.queryByLabelText('MongoDB login')).toBeNull();
    expect(screen.getByText('Sign in with MongoDB credentials only')).toBeTruthy();
  });

  it('goes straight to MongoDB login, without errors, when OpenShift is not offered', async () => {
    renderLogin(me());
    expect(screen.queryByText('Log in with OpenShift')).toBeNull();
    expect(screen.getByLabelText('MongoDB login')).toBeTruthy();
    expect(document.querySelector('.pf-m-danger')).toBeNull();
    await waitFor(() => expect(screen.getByText('Primary')).toBeTruthy());
    expect(screen.getByText(/Online/)).toBeTruthy();
  });

  it('explains an unavailable OpenShift sign-in as a warning, not a failure', () => {
    renderLogin(me({ auth: { ...me().auth, openshift: { state: 'unavailable', reason: 'unreachable' } } }), '/login?sso=unavailable');
    expect(screen.getByText('Single sign-on is not available right now')).toBeTruthy();
    expect(screen.getByLabelText('MongoDB login')).toBeTruthy();
  });

  it('asks only for MongoDB credentials after OpenShift sign-in', () => {
    renderLogin(me({ authenticated: true, sso: true, user: 'alice', source: 'openshift', roles: ['role:admin'] }));
    expect(screen.getByText('alice')).toBeTruthy();
    expect(screen.queryByText('Log in with OpenShift')).toBeNull();
    expect(screen.getByLabelText('MongoDB login')).toBeTruthy();
  });

  it('shows only single sign-on when it is required', () => {
    renderLogin(me({ auth: { ...me().auth, requireSSO: true, mongodbLogin: false, openshift: { state: 'available' } } }));
    expect(screen.getByText('Log in with OpenShift')).toBeTruthy();
    expect(screen.queryByText('Sign in with MongoDB credentials only')).toBeNull();
    expect(screen.queryByLabelText('MongoDB login')).toBeNull();
  });
});
