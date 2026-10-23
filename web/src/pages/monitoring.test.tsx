import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MonitoringPage } from './MonitoringPage';
import { tokenize } from '../lib/highlight';
import { RolesLabel } from '../components/Permission';
import type { MonitoringInfo } from '../api/types';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const json = (v: unknown) => new Response(JSON.stringify(v), { headers: { 'Content-Type': 'application/json' } });

function renderMonitoring(mon: MonitoringInfo, hello: Record<string, unknown> = {}) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) =>
      String(url).includes('/monitoring') ? json(mon) : json({ server: { build: { version: '8.0.4' }, hello }, tls: true, profile: 'prod' }),
    ),
  );
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <MonitoringPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const base = (sections: MonitoringInfo['sections']): MonitoringInfo => ({
  collectedAt: new Date().toISOString(),
  profile: 'prod',
  tls: true,
  session: { pool: { open: 2, inUse: 1, idle: 1 }, maxPoolSize: 20 },
  sections,
});

describe('monitoring page', () => {
  it('shows members, connections and total size for a clusterMonitor user', async () => {
    renderMonitoring(
      base({
        replicaSet: {
          data: {
            set: 'rs0',
            term: 4,
            members: [
              { name: 'db-0:27017', state: 'PRIMARY', health: 1, uptimeSeconds: 3600, pingMs: 0, self: true, syncSource: '', lastHeartbeatMessage: '', priority: 2, votes: 1 },
              { name: 'db-1:27017', state: 'SECONDARY', health: 1, uptimeSeconds: 3600, pingMs: 1, self: false, syncSource: 'db-0:27017', lastHeartbeatMessage: '', lagSeconds: 75 },
            ],
          },
        },
        connections: {
          data: {
            total: 12, active: 3, idle: 9, internalThreads: 20, clientGroups: 1, operations: [],
            byClient: [{ client: '10.0.0.7', appName: 'orders-api', user: 'orders', total: 12, active: 3, idle: 9 }],
          },
        },
        databases: { data: { totalSize: 3 * 1024 * 1024 * 1024, visibleSize: 1024, databases: [{ name: 'app', sizeOnDisk: 1024, empty: false }] } },
        server: { error: 'Your MongoDB user may not run serverStatus. The built-in clusterMonitor role grants it.', code: 'mongo_unauthorized' },
      }),
    );
    await waitFor(() => expect(screen.getAllByText('db-0:27017')).toHaveLength(2)); // member and sync source
    expect(screen.getByText('Primary')).toBeTruthy();
    expect(screen.getByText('Secondary')).toBeTruthy();
    expect(screen.getByText(/1m 15s/)).toBeTruthy(); // lag flagged
    expect(screen.getByText('orders-api')).toBeTruthy();
    expect(screen.getAllByText(/3\.0 GiB/).length).toBeGreaterThan(0);
    expect(screen.getByText('Server status needs more MongoDB privileges')).toBeTruthy();
  });

  it('falls back to the hello topology without clusterMonitor', async () => {
    const denied = { error: 'Your MongoDB user may not run X. The built-in clusterMonitor role grants it.', code: 'mongo_unauthorized' };
    renderMonitoring(
      base({ server: denied, host: denied, replicaSet: denied, connections: denied, databases: { data: { totalSize: 10, visibleSize: 10, databases: [] } } }),
      { setName: 'rs0', hosts: ['a:27017', 'b:27017'], primary: 'b:27017', me: 'a:27017' },
    );
    await waitFor(() => expect(screen.getByText('Most monitoring needs the clusterMonitor role')).toBeTruthy());
    await waitFor(() => expect(screen.getByText('a:27017')).toBeTruthy());
    expect(screen.getByText('Primary')).toBeTruthy();
    expect(screen.getByText('Secondary')).toBeTruthy();
  });
});

describe('shell highlighting', () => {
  it('round-trips the input and classifies tokens', () => {
    const code = 'db.orders.find({ qty: { $gt: 5 } }, "x") // note';
    const toks = tokenize(code);
    expect(toks.map((t) => t.text).join('')).toBe(code);
    expect(toks.find((t) => t.text === 'db')?.kind).toBe('builtin');
    expect(toks.find((t) => t.text === 'find')?.kind).toBe('property');
    expect(toks.find((t) => t.text === '5')?.kind).toBe('number');
    expect(toks.find((t) => t.text === '"x"')?.kind).toBe('string');
    expect(toks[toks.length - 1].kind).toBe('comment');
  });

  it('keeps unterminated strings and odd input intact', () => {
    for (const code of ['print("abc', '`multi\nline`', '@#Ã©', '']) expect(tokenize(code).map((t) => t.text).join('')).toBe(code);
  });
});

describe('role:mongodb label', () => {
  it('names the role that follows MongoDB privileges', () => {
    render(<RolesLabel roles={['role:mongodb']} compact />);
    expect(screen.getByText('MongoDB roles')).toBeTruthy();
  });
});
