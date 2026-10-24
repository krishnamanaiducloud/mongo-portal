import { useEffect, useRef, useState, type ReactNode } from 'react';
import { NavLink } from 'react-router';
import {
  Alert,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Flex,
  FlexItem,
  Grid,
  GridItem,
  Label,
  PageSection,
  Progress,
  ProgressMeasureLocation,
  ProgressVariant,
  Spinner,
  Title,
  ToggleGroup,
  ToggleGroupItem,
  Tooltip,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import {
  CheckCircleIcon,
  ExclamationCircleIcon,
  ExclamationTriangleIcon,
  InfoCircleIcon,
  LockIcon,
  StarIcon,
  SyncAltIcon,
  UnlockIcon,
} from '@patternfly/react-icons';
import { useMonitoring, useServerInfo } from '../api/hooks';
import type { MonitoringInfo, MonMember, MonSection, MonServer } from '../api/types';
import { formatBytes } from '../lib/ejson';
import { ErrorState } from './StatusPages';

// ---------- formatting ----------

const nf = new Intl.NumberFormat();
const fmt = (n: number | undefined) => (n === undefined || Number.isNaN(n) ? '—' : nf.format(Math.round(n)));
const fmtRate = (n: number) => (n >= 100 ? nf.format(Math.round(n)) : n.toFixed(n >= 10 ? 1 : 2));
const fmtBytesRate = (n: number) => `${formatBytes(n)}/s`;

function fmtDuration(sec: number | undefined): string {
  if (sec === undefined || !Number.isFinite(sec)) return '—';
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${Math.floor(sec % 60)}s`;
  return `${Math.floor(sec)}s`;
}

function fmtLag(sec: number | undefined): string {
  if (sec === undefined) return '—';
  return sec < 1 ? '< 1 s' : fmtDuration(sec);
}

const pct = (a: number, b: number) => (b > 0 ? Math.min(100, (a / b) * 100) : 0);

// ---------- samples for rates ----------

interface Sample {
  t: number;
  host: string;
  ops: number;
  bytesIn: number;
  bytesOut: number;
  current: number;
  cpuUs: number;
  authFailed: number;
  evictApp: number;
  lockWaitUs: number;
  readUs: number;
  readOps: number;
  writeUs: number;
  writeOps: number;
}

interface Rates {
  ops: number[];
  bytesIn: number[];
  bytesOut: number[];
  conns: number[];
  /** CPU time of mongod as percent of one core. */
  cpu: number[];
  /** Failed authentications between two polls. */
  authFailures: number[];
  /** Pages evicted by application threads per second (cache pressure). */
  appEvictions: number[];
  /** Milliseconds spent waiting for the global lock per second. */
  lockWait: number[];
  /** Average read and write latency in ms over each interval. */
  readLatency: number[];
  writeLatency: number[];
}

// One hour at the default 10 s refresh; long-term history belongs in
// Prometheus or MongoDB's own monitoring.
const MAX_SAMPLES = 360;

/** Keeps the recent serverStatus counters and derives per-second rates. */
function useRates(data: MonitoringInfo | undefined): Rates {
  const samples = useRef<Sample[]>([]);
  const [rates, setRates] = useState<Rates>({ ops: [], bytesIn: [], bytesOut: [], conns: [], cpu: [], authFailures: [], appEvictions: [], lockWait: [], readLatency: [], writeLatency: [] });
  const srv = data?.sections.server?.data;
  const at = data?.collectedAt;
  useEffect(() => {
    if (!srv || !at) return;
    const s: Sample = {
      t: Date.parse(at),
      host: srv.host,
      ops: Object.values(srv.opcounters).reduce((a, b) => a + b, 0),
      bytesIn: srv.network.bytesIn,
      bytesOut: srv.network.bytesOut,
      current: srv.connections.current,
      cpuUs: (srv.cpu?.user_time_us ?? 0) + (srv.cpu?.system_time_us ?? 0),
      authFailed: srv.authentication?.failed ?? 0,
      evictApp: srv.eviction?.applicationThreadPages ?? 0,
      lockWaitUs: srv.locks?.globalWaitMicros ?? 0,
      readUs: srv.latency?.reads.latencyMicros ?? 0,
      readOps: srv.latency?.reads.ops ?? 0,
      writeUs: srv.latency?.writes.latencyMicros ?? 0,
      writeOps: srv.latency?.writes.ops ?? 0,
    };
    let list = samples.current;
    const last = list[list.length - 1];
    if (last && last.t === s.t) return;
    // A different member (failover, new connection) or a restart resets the series.
    if (last && (last.host !== s.host || s.ops < last.ops)) list = [];
    list = [...list, s].slice(-MAX_SAMPLES);
    samples.current = list;
    const r: Rates = { ops: [], bytesIn: [], bytesOut: [], conns: list.map((x) => x.current), cpu: [], authFailures: [], appEvictions: [], lockWait: [], readLatency: [], writeLatency: [] };
    for (let i = 1; i < list.length; i++) {
      const a = list[i - 1];
      const b = list[i];
      const dt = (b.t - a.t) / 1000;
      if (dt <= 0) continue;
      const d = (x: number, y: number) => Math.max(0, y - x);
      r.ops.push(d(a.ops, b.ops) / dt);
      r.bytesIn.push(d(a.bytesIn, b.bytesIn) / dt);
      r.bytesOut.push(d(a.bytesOut, b.bytesOut) / dt);
      r.cpu.push((d(a.cpuUs, b.cpuUs) / 1e6 / dt) * 100);
      r.authFailures.push(d(a.authFailed, b.authFailed));
      r.appEvictions.push(d(a.evictApp, b.evictApp) / dt);
      r.lockWait.push(d(a.lockWaitUs, b.lockWaitUs) / 1000 / dt);
      const ro = d(a.readOps, b.readOps);
      const wo = d(a.writeOps, b.writeOps);
      r.readLatency.push(ro > 0 ? d(a.readUs, b.readUs) / ro / 1000 : 0);
      r.writeLatency.push(wo > 0 ? d(a.writeUs, b.writeUs) / wo / 1000 : 0);
    }
    setRates(r);
  }, [srv, at]);
  return rates;
}

// ---------- small visual pieces ----------

/** Single-series sparkline with a hover readout. */
function Sparkline({ values, format, label }: { values: number[]; format: (n: number) => string; label: string }) {
  const [hover, setHover] = useState<number | null>(null);
  if (values.length < 2) return <div className="portal-spark portal-spark-empty">Collecting samples…</div>;
  const w = 200;
  const h = 40;
  const max = Math.max(...values) || 1;
  const x = (i: number) => (i / (values.length - 1)) * w;
  const y = (v: number) => h - 2 - (v / max) * (h - 6);
  const line = values.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join('');
  const shown = hover ?? values.length - 1;
  return (
    <div className="portal-spark">
      <svg
        viewBox={`0 0 ${w} ${h}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={`${label}, last ${values.length} samples, latest ${format(values[values.length - 1])}, peak ${format(max)}`}
        onMouseMove={(e) => {
          const r = e.currentTarget.getBoundingClientRect();
          setHover(Math.round(((e.clientX - r.left) / r.width) * (values.length - 1)));
        }}
        onMouseLeave={() => setHover(null)}
      >
        <path d={`${line}L${w},${h}L0,${h}Z`} className="portal-spark-area" />
        <path d={line} className="portal-spark-line" vectorEffect="non-scaling-stroke" />
        {hover !== null && <line x1={x(hover)} x2={x(hover)} y1={0} y2={h} className="portal-spark-cursor" vectorEffect="non-scaling-stroke" />}
      </svg>
      <div className="portal-spark-readout" aria-hidden>
        {hover === null ? 'now' : `${values.length - 1 - hover} samples ago`} · {format(values[shown])}
      </div>
    </div>
  );
}

function StatTile({ label, value, unit, sub, children }: { label: string; value: ReactNode; unit?: string; sub?: ReactNode; children?: ReactNode }) {
  return (
    <Card isCompact className="portal-stat">
      <CardBody>
        <div className="portal-stat-label">{label}</div>
        <div className="portal-stat-value">
          {value}
          {unit && <span className="portal-stat-unit"> {unit}</span>}
        </div>
        {sub && <div className="portal-stat-sub">{sub}</div>}
        {children}
      </CardBody>
    </Card>
  );
}

function Meter({ title, value, max, label, warn = 75, danger = 90 }: { title: string; value: number; max: number; label: string; warn?: number; danger?: number }) {
  const p = pct(value, max);
  const variant = p >= danger ? ProgressVariant.danger : p >= warn ? ProgressVariant.warning : undefined;
  return (
    <Progress
      title={title}
      value={p}
      label={label}
      valueText={`${label} (${p.toFixed(0)}%)`}
      measureLocation={ProgressMeasureLocation.top}
      variant={variant}
      size="sm"
      className="pf-v6-u-mb-md"
    />
  );
}

/** Explains a section that could not be collected. */
function SectionNote({ s, what }: { s: MonSection<unknown> | undefined; what: string }) {
  if (!s?.error) return null;
  const unauthorized = s.code === 'mongo_unauthorized';
  return (
    <Alert
      isInline
      isPlain
      variant={unauthorized ? 'info' : 'warning'}
      title={unauthorized ? `${what} needs more MongoDB privileges` : `${what} is unavailable`}
      className="pf-v6-u-mb-sm"
    >
      {s.error}
    </Alert>
  );
}

function MemberState({ m }: { m: MonMember }) {
  if (m.health === 0 || ['DOWN', 'UNKNOWN', 'REMOVED'].includes(m.state)) {
    return (
      <Label color="red" icon={<ExclamationCircleIcon />} isCompact>
        {m.state || 'DOWN'}
      </Label>
    );
  }
  switch (m.state) {
    case 'PRIMARY':
      return (
        <Label color="green" icon={<StarIcon />} isCompact>
          Primary
        </Label>
      );
    case 'SECONDARY':
      return (
        <Label color="blue" icon={<CheckCircleIcon />} isCompact>
          Secondary
        </Label>
      );
    case 'ARBITER':
      return (
        <Label color="grey" isCompact>
          Arbiter
        </Label>
      );
    default:
      return (
        <Label color="orange" icon={<ExclamationTriangleIcon />} isCompact>
          {m.state}
        </Label>
      );
  }
}

function LagCell({ m }: { m: MonMember }) {
  if (m.state === 'PRIMARY' || m.arbiterOnly) return <>—</>;
  const lag = m.lagSeconds;
  if (lag === undefined) return <>—</>;
  if (lag >= 60)
    return (
      <span className="portal-status-danger">
        <ExclamationCircleIcon /> {fmtLag(lag)}
      </span>
    );
  if (lag >= 10)
    return (
      <span className="portal-status-warning">
        <ExclamationTriangleIcon /> {fmtLag(lag)}
      </span>
    );
  return <>{fmtLag(lag)}</>;
}

// ---------- sections ----------

function ReplicaSetCard({ data, hello }: { data: MonitoringInfo; hello?: HelloInfo }) {
  const sec = data.sections.replicaSet;
  const rs = sec?.data;
  const members = rs?.members ?? [];
  const counts = members.reduce<Record<string, number>>((a, m) => ({ ...a, [m.state]: (a[m.state] ?? 0) + 1 }), {});
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          Topology
          {rs?.set && (
            <span className="portal-card-sub">
              {' '}
              · replica set <strong>{rs.set}</strong>
              {rs.term !== undefined && <> · term {rs.term}</>}
            </span>
          )}
        </CardTitle>
      </CardHeader>
      <CardBody>
        {rs?.standalone && <div>Standalone server (no replica set).</div>}
        {members.length > 0 && (
          <>
            <Flex gap={{ default: 'gapMd' }} className="pf-v6-u-mb-sm portal-muted">
              <FlexItem>{members.length} members</FlexItem>
              <FlexItem>{counts.PRIMARY ?? 0} primary</FlexItem>
              <FlexItem>{counts.SECONDARY ?? 0} secondary</FlexItem>
              {counts.ARBITER ? <FlexItem>{counts.ARBITER} arbiter</FlexItem> : null}
              {rs?.writeMajorityCount ? <FlexItem>write majority {rs.writeMajorityCount}</FlexItem> : null}
              {rs?.lastElection?.date && (
                <FlexItem>
                  last election {new Date(rs.lastElection.date).toLocaleString()}
                  {rs.lastElection.reason ? ` (${rs.lastElection.reason})` : ''}
                </FlexItem>
              )}
            </Flex>
            <Table aria-label="Replica set members" variant="compact">
              <Thead>
                <Tr>
                  <Th>Member</Th>
                  <Th>State</Th>
                  <Th>Replication lag</Th>
                  <Th>Ping</Th>
                  <Th>Syncs from</Th>
                  <Th>Priority / votes</Th>
                  <Th>Uptime</Th>
                </Tr>
              </Thead>
              <Tbody>
                {members.map((m) => (
                  <Tr key={m.name}>
                    <Td dataLabel="Member">
                      <span className="portal-mono">{m.name}</span>
                      {m.self && (
                        <Tooltip content="The member the portal is connected to for this request">
                          <Label isCompact className="pf-v6-u-ml-sm">
                            connected
                          </Label>
                        </Tooltip>
                      )}
                      {m.hidden && (
                        <Label isCompact className="pf-v6-u-ml-sm">
                          hidden
                        </Label>
                      )}
                      {m.lastHeartbeatMessage && <div className="portal-muted portal-small">{m.lastHeartbeatMessage}</div>}
                    </Td>
                    <Td dataLabel="State">
                      <MemberState m={m} />
                    </Td>
                    <Td dataLabel="Replication lag">
                      <LagCell m={m} />
                    </Td>
                    <Td dataLabel="Ping">{m.self ? '—' : `${fmt(m.pingMs)} ms`}</Td>
                    <Td dataLabel="Syncs from" className="portal-mono">
                      {m.syncSource || '—'}
                    </Td>
                    <Td dataLabel="Priority / votes">
                      {m.priority !== undefined ? `${m.priority} / ${m.votes ?? '—'}` : '—'}
                    </Td>
                    <Td dataLabel="Uptime">{fmtDuration(m.uptimeSeconds)}</Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          </>
        )}
        {sec?.error && (
          <>
            <SectionNote s={sec} what="Replica set status" />
            {hello?.hosts?.length ? <HelloTopology hello={hello} /> : null}
          </>
        )}
      </CardBody>
    </Card>
  );
}

interface HelloInfo {
  setName?: string;
  hosts?: string[];
  passives?: string[];
  arbiters?: string[];
  primary?: string;
  me?: string;
  msg?: string;
}

/** Topology from the hello handshake, available to every user. */
function HelloTopology({ hello }: { hello: HelloInfo }) {
  const rows = [
    ...(hello.hosts ?? []).map((h) => ({ h, role: h === hello.primary ? 'Primary' : 'Secondary' })),
    ...(hello.passives ?? []).map((h) => ({ h, role: 'Passive secondary' })),
    ...(hello.arbiters ?? []).map((h) => ({ h, role: 'Arbiter' })),
  ];
  return (
    <>
      <div className="portal-muted pf-v6-u-mb-sm">
        From the connection handshake{hello.setName ? <> · replica set <strong>{hello.setName}</strong></> : null}:
      </div>
      <Table aria-label="Replica set members from hello" variant="compact">
        <Thead>
          <Tr>
            <Th>Member</Th>
            <Th>Role</Th>
          </Tr>
        </Thead>
        <Tbody>
          {rows.map((r) => (
            <Tr key={r.h}>
              <Td dataLabel="Member" className="portal-mono">
                {r.h}
                {r.h === hello.me && (
                  <Label isCompact className="pf-v6-u-ml-sm">
                    connected
                  </Label>
                )}
              </Td>
              <Td dataLabel="Role">
                {r.role === 'Primary' ? (
                  <Label color="green" icon={<StarIcon />} isCompact>
                    Primary
                  </Label>
                ) : (
                  <Label color={r.role === 'Arbiter' ? 'grey' : 'blue'} isCompact>
                    {r.role}
                  </Label>
                )}
              </Td>
            </Tr>
          ))}
        </Tbody>
      </Table>
    </>
  );
}

function ConnectionsCard({ data, srv }: { data: MonitoringInfo; srv?: MonServer }) {
  const sec = data.sections.connections;
  const c = sec?.data;
  const pool = data.session.pool;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Connections</CardTitle>
      </CardHeader>
      <CardBody>
        {srv && (
          <Meter
            title="Connections in use on this member"
            value={srv.connections.current}
            max={srv.connections.current + srv.connections.available}
            label={`${fmt(srv.connections.current)} of ${fmt(srv.connections.current + srv.connections.available)}`}
          />
        )}
        {c && (
          <>
            <div className="portal-split" role="img" aria-label={`${c.active} active and ${c.idle} idle client connections`}>
              <span className="portal-split-active" style={{ flexGrow: c.active || 0 }} />
              <span className="portal-split-idle" style={{ flexGrow: c.idle || 0 }} />
            </div>
            <Flex gap={{ default: 'gapLg' }} className="pf-v6-u-mb-md pf-v6-u-mt-sm">
              <FlexItem>
                <span className="portal-swatch portal-split-active" /> <strong>{fmt(c.active)}</strong> active
              </FlexItem>
              <FlexItem>
                <span className="portal-swatch portal-split-idle" /> <strong>{fmt(c.idle)}</strong> idle
              </FlexItem>
              <FlexItem className="portal-muted">
                {fmt(c.total)} client connections · {fmt(c.internalThreads)} internal threads
              </FlexItem>
            </Flex>
            <Table aria-label="Connections by client" variant="compact" isStickyHeader>
              <Thead>
                <Tr>
                  <Th>Client host</Th>
                  <Th>Application</Th>
                  <Th>User</Th>
                  <Th>Total</Th>
                  <Th>Active</Th>
                  <Th>Idle</Th>
                </Tr>
              </Thead>
              <Tbody>
                {c.byClient.map((g) => (
                  <Tr key={`${g.client}|${g.appName}|${g.user}`}>
                    <Td dataLabel="Client host" className="portal-mono">
                      {g.client}
                    </Td>
                    <Td dataLabel="Application">{g.appName || <span className="portal-muted">unnamed</span>}</Td>
                    <Td dataLabel="User">{g.user || <span className="portal-muted">—</span>}</Td>
                    <Td dataLabel="Total">{fmt(g.total)}</Td>
                    <Td dataLabel="Active">{fmt(g.active)}</Td>
                    <Td dataLabel="Idle">{fmt(g.idle)}</Td>
                  </Tr>
                ))}
                {c.byClient.length === 0 && (
                  <Tr>
                    <Td colSpan={6}>No client connections.</Td>
                  </Tr>
                )}
              </Tbody>
            </Table>
            {c.clientGroups > c.byClient.length && (
              <div className="portal-muted portal-small pf-v6-u-mt-sm">
                Showing the {c.byClient.length} largest of {c.clientGroups} client groups.
              </div>
            )}
          </>
        )}
        <SectionNote s={sec} what="Connection details" />
        <div className="portal-subhead">Your portal session pool</div>
        <Flex gap={{ default: 'gapLg' }}>
          <FlexItem>
            <strong>{fmt(pool.open)}</strong> open
          </FlexItem>
          <FlexItem>
            <strong>{fmt(pool.inUse)}</strong> in use
          </FlexItem>
          <FlexItem>
            <strong>{fmt(pool.idle)}</strong> idle
          </FlexItem>
          {data.session.maxPoolSize > 0 && <FlexItem className="portal-muted">limit {fmt(data.session.maxPoolSize)} per member</FlexItem>}
        </Flex>
      </CardBody>
    </Card>
  );
}

function ResourcesCard({ data, srv }: { data: MonitoringInfo; srv?: MonServer }) {
  const host = data.sections.host?.data;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Resources</CardTitle>
      </CardHeader>
      <CardBody>
        {srv && (
          <>
            {srv.cache.maxBytes > 0 && (
              <Meter
                title="WiredTiger cache"
                value={srv.cache.bytesInCache}
                max={srv.cache.maxBytes}
                label={`${formatBytes(srv.cache.bytesInCache)} of ${formatBytes(srv.cache.maxBytes)}`}
                warn={85}
                danger={95}
              />
            )}
            {srv.cache.maxBytes > 0 && (
              <Meter
                title="Dirty cache"
                value={srv.cache.dirtyBytes}
                max={srv.cache.maxBytes}
                label={formatBytes(srv.cache.dirtyBytes)}
                warn={5}
                danger={20}
              />
            )}
            {host?.memSizeMB ? (
              <Meter
                title="Resident memory"
                value={srv.memoryMB.resident}
                max={host.memLimitMB || host.memSizeMB}
                label={`${formatBytes(srv.memoryMB.resident * 1048576)} of ${formatBytes((host.memLimitMB || host.memSizeMB) * 1048576)}`}
              />
            ) : null}
            <DescriptionList isCompact isHorizontal columnModifier={{ default: '2Col' }}>
              <Desc term="Read / write queue">
                {fmt(srv.queue.readers)} / {fmt(srv.queue.writers)}
              </Desc>
              <Desc term="Active readers / writers">
                {fmt(srv.activeClients.readers)} / {fmt(srv.activeClients.writers)}
              </Desc>
              <Desc term="Open transactions">{fmt(srv.transactions.currentOpen)}</Desc>
              <Desc term="Committed / aborted">
                {fmt(srv.transactions.totalCommitted)} / {fmt(srv.transactions.totalAborted)}
              </Desc>
              <Desc term="Virtual memory">{formatBytes(srv.memoryMB.virtual * 1048576)}</Desc>
              <Desc term="Rejected connections">{fmt(srv.connections.rejected)}</Desc>
              <Desc term="Asserts (regular / warning / user)">
                {fmt(srv.asserts.regular)} / {fmt(srv.asserts.warning)} / {fmt(srv.asserts.user)}
              </Desc>
              <Desc term="Connections created">{fmt(srv.connections.totalCreated)}</Desc>
            </DescriptionList>
          </>
        )}
        <SectionNote s={data.sections.server} what="Server status" />
        {host && (
          <>
            <div className="portal-subhead">Host</div>
            <DescriptionList isCompact isHorizontal columnModifier={{ default: '2Col' }}>
              <Desc term="Hostname">
                <span className="portal-mono">{host.hostname}</span>
              </Desc>
              <Desc term="OS">{host.os || '—'}</Desc>
              <Desc term="CPU">
                {fmt(host.numCores)} cores · {host.cpuArch}
              </Desc>
              <Desc term="Memory">
                {formatBytes(host.memSizeMB * 1048576)}
                {host.memLimitMB && host.memLimitMB < host.memSizeMB ? ` (limit ${formatBytes(host.memLimitMB * 1048576)})` : ''}
              </Desc>
            </DescriptionList>
          </>
        )}
        <SectionNote s={data.sections.host} what="Host information" />
      </CardBody>
    </Card>
  );
}

function Desc({ term, children }: { term: string; children: ReactNode }) {
  return (
    <DescriptionListGroup>
      <DescriptionListTerm>{term}</DescriptionListTerm>
      <DescriptionListDescription>{children}</DescriptionListDescription>
    </DescriptionListGroup>
  );
}

function OpcountersCard({ srv, rates }: { srv: MonServer; rates: Rates }) {
  const entries = Object.entries(srv.opcounters) as [keyof MonServer['opcounters'], number][];
  const total = entries.reduce((a, [, v]) => a + v, 0);
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          Operations <span className="portal-card-sub">· since start</span>
        </CardTitle>
      </CardHeader>
      <CardBody>
        <Table aria-label="Operation counters" variant="compact">
          <Thead>
            <Tr>
              <Th>Type</Th>
              <Th>Count</Th>
              <Th>Share</Th>
            </Tr>
          </Thead>
          <Tbody>
            {entries.map(([k, v]) => (
              <Tr key={k}>
                <Td dataLabel="Type">{k}</Td>
                <Td dataLabel="Count">{fmt(v)}</Td>
                <Td dataLabel="Share">
                  <div className="portal-bar" title={`${pct(v, total).toFixed(1)}%`}>
                    <span style={{ width: `${pct(v, total)}%` }} />
                  </div>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
        <div className="portal-muted portal-small pf-v6-u-mt-sm">
          {rates.ops.length ? `${fmtRate(rates.ops[rates.ops.length - 1])} operations/s now` : 'Rates appear after the next refresh.'}
        </div>
      </CardBody>
    </Card>
  );
}

function OperationsCard({ data }: { data: MonitoringInfo }) {
  const c = data.sections.connections?.data;
  if (!c) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          Active operations{' '}
          <span className="portal-card-sub">
            · longest running first, excluding this portal
            {c.expectedWaits ? ` · ${c.expectedWaits} expected waits (change streams, tailable cursors, driver monitoring) are not slow` : ''}
          </span>
        </CardTitle>
      </CardHeader>
      <CardBody className="pf-v6-u-pt-0 pf-v6-u-pb-0">
        <NavLink to="/operations">All operations and idle connections, with filters and killOp →</NavLink>
      </CardBody>
      <CardBody>
        {c.operations.length === 0 ? (
          <div className="portal-muted">
            <CheckCircleIcon className="portal-status-success" /> No client operations running right now.
          </div>
        ) : (
          <Table aria-label="Active operations" variant="compact">
            <Thead>
              <Tr>
                <Th>Op</Th>
                <Th>Namespace</Th>
                <Th>Running</Th>
                <Th>Client</Th>
                <Th>User</Th>
                <Th>Plan</Th>
              </Tr>
            </Thead>
            <Tbody>
              {c.operations.map((o, i) => (
                <Tr key={`${String(o.opid)}-${i}`}>
                  <Td dataLabel="Op">
                    {o.op}
                    {o.waitingForLock && (
                      <Label color="orange" isCompact icon={<ExclamationTriangleIcon />} className="pf-v6-u-ml-sm">
                        waiting for lock
                      </Label>
                    )}
                    {o.expectedWait && (
                      <Label color="teal" isCompact className="pf-v6-u-ml-sm" title={`${o.expectedWait}; not counted as slow`}>
                        expected wait
                      </Label>
                    )}
                  </Td>
                  <Td dataLabel="Namespace" className="portal-mono">
                    {o.ns || '—'}
                  </Td>
                  <Td dataLabel="Running">{fmtDuration(o.secsRunning)}</Td>
                  <Td dataLabel="Client" className="portal-mono">
                    {o.client}
                    {o.appName && <div className="portal-muted portal-small">{o.appName}</div>}
                  </Td>
                  <Td dataLabel="User">{o.user || '—'}</Td>
                  <Td dataLabel="Plan" className="portal-mono">
                    {o.planSummary || '—'}
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </CardBody>
    </Card>
  );
}

function DatabasesCard({ data }: { data: MonitoringInfo }) {
  const sec = data.sections.databases;
  const d = sec?.data;
  const max = Math.max(1, ...(d?.databases ?? []).map((x) => x.sizeOnDisk));
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          Storage
          {d && (
            <span className="portal-card-sub">
              {' '}
              · {formatBytes(d.totalSize)} on disk
            </span>
          )}
        </CardTitle>
      </CardHeader>
      <CardBody>
        {d && (
          <>
            {d.visibleSize < d.totalSize && (
              <div className="portal-muted portal-small pf-v6-u-mb-sm">
                {formatBytes(d.visibleSize)} in the databases your portal role shows; the total covers every database MongoDB lists for you.
              </div>
            )}
            <Table aria-label="Database sizes" variant="compact">
              <Thead>
                <Tr>
                  <Th>Database</Th>
                  <Th>Size on disk</Th>
                  <Th>Share of total</Th>
                </Tr>
              </Thead>
              <Tbody>
                {d.databases.map((x) => (
                  <Tr key={x.name}>
                    <Td dataLabel="Database">
                      <NavLink to={`/db/${encodeURIComponent(x.name)}`}>{x.name}</NavLink>
                    </Td>
                    <Td dataLabel="Size on disk">{formatBytes(x.sizeOnDisk)}</Td>
                    <Td dataLabel="Share of total">
                      <Flex alignItems={{ default: 'alignItemsCenter' }} gap={{ default: 'gapSm' }} flexWrap={{ default: 'nowrap' }}>
                        <div className="portal-bar">
                          <span style={{ width: `${pct(x.sizeOnDisk, max)}%` }} />
                        </div>
                        <span className="portal-small portal-muted">{pct(x.sizeOnDisk, d.totalSize).toFixed(1)}%</span>
                      </Flex>
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          </>
        )}
        <SectionNote s={sec} what="Database sizes" />
      </CardBody>
    </Card>
  );
}

// ---------- page ----------

const INTERVALS: [string, number | false][] = [
  ['Off', false],
  ['5s', 5000],
  ['10s', 10_000],
  ['30s', 30_000],
];

function PerformanceCard({ srv, rates }: { srv: MonServer; rates: Rates }) {
  const last = (a: number[]) => (a.length ? a[a.length - 1] : undefined);
  const avg = (lat?: { latencyMicros: number; ops: number }) => (lat && lat.ops > 0 ? lat.latencyMicros / lat.ops / 1000 : undefined);
  const items: { label: string; v?: number; fmt: (n: number) => string; series: number[]; sub: string }[] = [
    { label: 'Read latency', v: last(rates.readLatency), fmt: (n) => `${n.toFixed(2)} ms`, series: rates.readLatency, sub: `since start ${avg(srv.latency?.reads)?.toFixed(2) ?? '—'} ms` },
    { label: 'Write latency', v: last(rates.writeLatency), fmt: (n) => `${n.toFixed(2)} ms`, series: rates.writeLatency, sub: `since start ${avg(srv.latency?.writes)?.toFixed(2) ?? '—'} ms` },
    { label: 'CPU (mongod)', v: last(rates.cpu), fmt: (n) => `${n.toFixed(0)}% of a core`, series: rates.cpu, sub: `${fmt(srv.cpu?.page_faults)} page faults since start` },
    { label: 'Global lock wait', v: last(rates.lockWait), fmt: (n) => `${n.toFixed(1)} ms/s`, series: rates.lockWait, sub: `${fmt(srv.locks?.globalWaitCount)} waits since start` },
    { label: 'Evictions by app threads', v: last(rates.appEvictions), fmt: (n) => `${fmtRate(n)}/s`, series: rates.appEvictions, sub: 'non-zero means the cache cannot keep up' },
    { label: 'Failed authentications', v: last(rates.authFailures), fmt: (n) => `${fmt(n)} per refresh`, series: rates.authFailures, sub: `${fmt(srv.authentication?.failed)} since start` },
  ];
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          Performance <span className="portal-card-sub">· per refresh, this member</span>
        </CardTitle>
      </CardHeader>
      <CardBody>
        <Grid hasGutter>
          {items.map((i) => (
            <GridItem key={i.label} md={6} xl={4}>
              <div className="portal-stat-label">{i.label}</div>
              <div className="portal-stat-value portal-stat-value-sm">{i.v !== undefined ? i.fmt(i.v) : '—'}</div>
              <div className="portal-stat-sub">{i.sub}</div>
              <Sparkline values={i.series} format={i.fmt} label={i.label} />
            </GridItem>
          ))}
        </Grid>
        {srv.tickets && (
          <div className="portal-small portal-muted pf-v6-u-mt-md">
            Execution tickets: read {fmt(srv.tickets.readOut)} in use / {fmt(srv.tickets.readAvailable)} free · write {fmt(srv.tickets.writeOut)} in use /{' '}
            {fmt(srv.tickets.writeAvailable)} free
          </div>
        )}
      </CardBody>
    </Card>
  );
}

function OplogCard({ data }: { data: MonitoringInfo }) {
  const sec = data.sections.oplog;
  const o = sec?.data;
  const warn = data.thresholds?.oplogWindowWarningSeconds ?? 86400;
  return (
    <Card isFullHeight>
      <CardHeader>
        <CardTitle>Oplog</CardTitle>
      </CardHeader>
      <CardBody>
        {o?.available ? (
          <>
            <div className="portal-stat-label">Window</div>
            <div className={`portal-stat-value ${o.windowSeconds !== undefined && o.windowSeconds < warn ? 'portal-status-warning' : ''}`}>
              {fmtDuration(o.windowSeconds)}
            </div>
            <div className="portal-stat-sub">How long a secondary may be offline and still catch up without a full resync.</div>
            {o.maxSizeBytes ? (
              <Meter title="Oplog size" value={o.sizeBytes ?? 0} max={o.maxSizeBytes} label={`${formatBytes(o.sizeBytes)} of ${formatBytes(o.maxSizeBytes)}`} warn={101} danger={101} />
            ) : null}
            <div className="portal-small portal-muted">
              {o.first && `first entry ${new Date(o.first).toLocaleString()}`} · {o.last && `last ${new Date(o.last).toLocaleString()}`}
            </div>
          </>
        ) : o && !o.available ? (
          <div className="portal-muted">No oplog (standalone server).</div>
        ) : null}
        <SectionNote s={sec} what="The oplog window" />
      </CardBody>
    </Card>
  );
}

function StorageStatsCard({ data }: { data: MonitoringInfo }) {
  const stats = data.sections.databases?.data?.stats ?? [];
  if (stats.length === 0) return null;
  const fs = stats.find((s) => s.fsTotalSize > 0);
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          Database statistics <span className="portal-card-sub">· dbStats of the largest databases</span>
        </CardTitle>
      </CardHeader>
      <CardBody>
        {fs && (
          <Meter title="Data volume" value={fs.fsUsedSize} max={fs.fsTotalSize} label={`${formatBytes(fs.fsUsedSize)} used of ${formatBytes(fs.fsTotalSize)}`} warn={80} danger={90} />
        )}
        <Table aria-label="Database statistics" variant="compact">
          <Thead>
            <Tr>
              <Th>Database</Th>
              <Th>Collections</Th>
              <Th>Documents</Th>
              <Th>Data size</Th>
              <Th>Storage</Th>
              <Th>Indexes</Th>
            </Tr>
          </Thead>
          <Tbody>
            {stats.map((s) => (
              <Tr key={s.name}>
                <Td dataLabel="Database">
                  <NavLink to={`/db/${encodeURIComponent(s.name)}`}>{s.name}</NavLink>
                </Td>
                <Td dataLabel="Collections">{fmt(s.collections)}</Td>
                <Td dataLabel="Documents">{fmt(s.objects)}</Td>
                <Td dataLabel="Data size">{formatBytes(s.dataSize)}</Td>
                <Td dataLabel="Storage">
                  {formatBytes(s.storageSize)}
                  {s.dataSize > 0 && <span className="portal-muted portal-small"> · {((s.storageSize / s.dataSize) * 100).toFixed(0)}% of data (compression)</span>}
                </Td>
                <Td dataLabel="Indexes">
                  {formatBytes(s.indexSize)} <span className="portal-muted portal-small">({fmt(s.indexes)})</span>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      </CardBody>
    </Card>
  );
}

const alertVariant = { critical: 'danger', warning: 'warning', info: 'info' } as const;

function Ago({ at }: { at: string }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  const s = Math.max(0, Math.round((now - Date.parse(at)) / 1000));
  return <>{s < 2 ? 'just now' : `${s}s ago`}</>;
}

export function MonitoringPage() {
  const [interval, setIntervalMs] = useState<number | false>(10_000);
  const q = useMonitoring(interval);
  const info = useServerInfo();
  const rates = useRates(q.data);
  const hello = (info.data?.server as { hello?: HelloInfo } | undefined)?.hello;
  const build = (info.data?.server as { build?: { version?: string } } | undefined)?.build;

  const header = (
    <Flex alignItems={{ default: 'alignItemsCenter' }} gap={{ default: 'gapMd' }} className="pf-v6-u-mb-md">
      <Title headingLevel="h1">Monitoring</Title>
      {q.data && (
        <>
          <Label isCompact>Profile {q.data.profile}</Label>
          <Label isCompact color={q.data.tls ? 'green' : 'orange'} icon={q.data.tls ? <LockIcon /> : <UnlockIcon />}>
            {q.data.tls ? 'TLS' : 'Plaintext'}
          </Label>
        </>
      )}
      <Flex className="pf-v6-u-ml-auto" alignItems={{ default: 'alignItemsCenter' }} gap={{ default: 'gapSm' }}>
        {q.data && (
          <span className="portal-muted portal-small" aria-live="off">
            Updated <Ago at={q.data.collectedAt} />
          </span>
        )}
        <ToggleGroup isCompact aria-label="Refresh interval">
          {INTERVALS.map(([label, ms]) => (
            <ToggleGroupItem key={label} text={label} isSelected={interval === ms} onChange={() => setIntervalMs(ms)} />
          ))}
        </ToggleGroup>
        <Tooltip content="Refresh now">
          <Button variant="plain" aria-label="Refresh now" icon={q.isFetching ? <Spinner size="sm" aria-label="Refreshing" /> : <SyncAltIcon />} onClick={() => void q.refetch()} />
        </Tooltip>
      </Flex>
    </Flex>
  );

  if (q.isPending)
    return (
      <PageSection>
        {header}
        <Spinner aria-label="Loading monitoring" />
      </PageSection>
    );
  if (q.isError && !q.data)
    return (
      <PageSection>
        {header}
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      </PageSection>
    );

  const data = q.data;
  const srv = data.sections.server?.data;
  const conns = data.sections.connections?.data;
  const dbs = data.sections.databases?.data;
  const lastOf = (a: number[]) => (a.length ? a[a.length - 1] : undefined);
  const privileged = ['server', 'replicaSet', 'connections', 'host'] as const;
  const missing = privileged.filter((k) => data.sections[k]?.code === 'mongo_unauthorized');

  return (
    <PageSection>
      {header}
      {missing.length === privileged.length && (
        <Alert variant="info" isInline className="pf-v6-u-mb-md" title="Most monitoring needs the clusterMonitor role">
          Your MongoDB user can see database sizes and the topology from the connection handshake. Ask a database administrator to grant the
          built-in <code>clusterMonitor</code> role for server status, replica set health, connections and operations.
        </Alert>
      )}
      {q.isError && (
        <Alert variant="warning" isInline isPlain className="pf-v6-u-mb-md" title="The last refresh failed; showing the previous values." />
      )}
      {(data.alerts ?? []).length > 0 && (
        <div className="pf-v6-u-mb-md" role="status" aria-label="Alerts">
          {(data.alerts ?? []).map((a, i) => (
            <Alert key={i} variant={alertVariant[a.severity]} isInline isPlain title={a.message} />
          ))}
        </div>
      )}
      <Grid hasGutter>
        <GridItem sm={6} xl={3}>
          <StatTile
            label="Connections"
            value={srv ? fmt(srv.connections.current) : conns ? fmt(conns.total) : '—'}
            sub={srv ? `${fmt(srv.connections.available)} available · ${fmt(srv.connections.active)} active` : conns ? `${fmt(conns.active)} active · ${fmt(conns.idle)} idle` : 'needs clusterMonitor'}
          >
            {srv && <Sparkline values={rates.conns} format={(n) => `${fmt(n)} connections`} label="Current connections" />}
          </StatTile>
        </GridItem>
        <GridItem sm={6} xl={3}>
          <StatTile
            label="Operations"
            value={lastOf(rates.ops) !== undefined ? fmtRate(lastOf(rates.ops)!) : '—'}
            unit="/s"
            sub={srv ? `${fmt(srv.activeClients.total)} active clients · queue ${fmt(srv.queue.total)}` : 'needs clusterMonitor'}
          >
            {srv && <Sparkline values={rates.ops} format={(n) => `${fmtRate(n)} ops/s`} label="Operations per second" />}
          </StatTile>
        </GridItem>
        <GridItem sm={6} xl={3}>
          <StatTile
            label="Network in"
            value={lastOf(rates.bytesIn) !== undefined ? formatBytes(lastOf(rates.bytesIn)!) : '—'}
            unit="/s"
            sub={srv ? `out ${lastOf(rates.bytesOut) !== undefined ? fmtBytesRate(lastOf(rates.bytesOut)!) : '—'} · ${fmt(srv.network.numRequests)} requests` : 'needs clusterMonitor'}
          >
            {srv && <Sparkline values={rates.bytesIn} format={fmtBytesRate} label="Network bytes in per second" />}
          </StatTile>
        </GridItem>
        <GridItem sm={6} xl={3}>
          <StatTile
            label="Data on disk"
            value={dbs ? formatBytes(dbs.totalSize) : '—'}
            sub={
              <>
                {dbs ? `${dbs.databases.length} databases` : 'unavailable'}
                {srv && (
                  <>
                    {' '}
                    · up {fmtDuration(srv.uptimeSeconds)} · {srv.version || build?.version}
                  </>
                )}
                {!srv && build?.version && <> · MongoDB {build.version}</>}
              </>
            }
          />
        </GridItem>
        <GridItem lg={8}>
          <ReplicaSetCard data={data} hello={hello} />
        </GridItem>
        <GridItem lg={4}>
          <OplogCard data={data} />
        </GridItem>
        {srv && (
          <GridItem span={12}>
            <PerformanceCard srv={srv} rates={rates} />
          </GridItem>
        )}
        <GridItem lg={7}>
          <ConnectionsCard data={data} srv={srv} />
        </GridItem>
        <GridItem lg={5}>
          <ResourcesCard data={data} srv={srv} />
        </GridItem>
        <GridItem span={12}>
          <OperationsCard data={data} />
        </GridItem>
        <GridItem lg={7}>
          <DatabasesCard data={data} />
        </GridItem>
        {srv && (
          <GridItem lg={5}>
            <OpcountersCard srv={srv} rates={rates} />
          </GridItem>
        )}
        <GridItem span={12}>
          <StorageStatsCard data={data} />
        </GridItem>
      </Grid>
      <MonitoringFootnote />
    </PageSection>
  );
}

function MonitoringFootnote() {
  return (
    <div className="portal-muted portal-small pf-v6-u-mt-md">
      <InfoCircleIcon /> Collected with your own MongoDB session, so you see what your MongoDB roles allow. Values describe the member the
      portal is connected to; rates are computed between refreshes.
    </div>
  );
}
