import { NavLink } from 'react-router';
import {
  Alert,
  Button,
  Card,
  CardBody,
  CardFooter,
  CardTitle,
  Content,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Flex,
  Grid,
  GridItem,
  Label,
  PageSection,
  Spinner,
  Title,
} from '@patternfly/react-core';
import {
  CheckCircleIcon,
  ClipboardCheckIcon,
  CubesIcon,
  ExchangeAltIcon,
  ExclamationCircleIcon,
  ExclamationTriangleIcon,
  HistoryIcon,
  InfoCircleIcon,
  ListIcon,
  LockIcon,
  ServerIcon,
  TerminalIcon,
  UnlockIcon,
} from '@patternfly/react-icons';
import { useAuditSearch, useMonitoring, useSession, useStatus } from '../api/hooks';
import type { Me, MonAlert } from '../api/types';
import { HealthLabel, IdentityLabel, sourceDescription } from '../components/Indicators';
import { RolesLabel } from '../components/Permission';
import { formatBytes } from '../lib/ejson';

const alertIcon = { critical: <ExclamationCircleIcon className="portal-status-danger" />, warning: <ExclamationTriangleIcon className="portal-status-warning" />, info: <InfoCircleIcon /> };

function Health({ me }: { me: Me }) {
  const canMonitor = me.permissions['monitoring:get'] !== false;
  const mon = useMonitoring(canMonitor ? 30_000 : false);
  if (!canMonitor) return <Content component="p">Your portal role does not include monitoring.</Content>;
  if (mon.isPending) return <Spinner size="md" aria-label="Loading health" />;
  if (mon.isError || !mon.data) return <Content component="p">Monitoring is not available for this session.</Content>;
  const d = mon.data;
  const rs = d.sections.replicaSet?.data;
  const srv = d.sections.server?.data;
  const dbs = d.sections.databases?.data;
  const alerts: MonAlert[] = d.alerts ?? [];
  const primaries = rs?.members?.filter((m) => m.state === 'PRIMARY').length ?? 0;
  return (
    <>
      {alerts.length === 0 ? (
        <Flex className="pf-v6-u-mb-md" alignItems={{ default: 'alignItemsCenter' }} gap={{ default: 'gapSm' }}>
          <CheckCircleIcon className="portal-status-success" /> No alerts for the thresholds configured.
        </Flex>
      ) : (
        alerts.slice(0, 5).map((a, i) => (
          <Alert key={i} isInline isPlain variant={a.severity === 'critical' ? 'danger' : a.severity === 'warning' ? 'warning' : 'info'} title={a.message} customIcon={alertIcon[a.severity]} />
        ))
      )}
      <DescriptionList isCompact isHorizontal columnModifier={{ default: '2Col' }}>
        <DescriptionListGroup>
          <DescriptionListTerm>Topology</DescriptionListTerm>
          <DescriptionListDescription>
            {rs?.set ? `Replica set ${rs.set}: ${rs.members?.length ?? 0} members, ${primaries} primary` : rs?.standalone ? 'Standalone' : '—'}
          </DescriptionListDescription>
        </DescriptionListGroup>
        <DescriptionListGroup>
          <DescriptionListTerm>Connections</DescriptionListTerm>
          <DescriptionListDescription>{srv ? `${srv.connections.current.toLocaleString()} of ${(srv.connections.current + srv.connections.available).toLocaleString()}` : '—'}</DescriptionListDescription>
        </DescriptionListGroup>
        <DescriptionListGroup>
          <DescriptionListTerm>Data on disk</DescriptionListTerm>
          <DescriptionListDescription>{dbs ? formatBytes(dbs.totalSize) : '—'}</DescriptionListDescription>
        </DescriptionListGroup>
        <DescriptionListGroup>
          <DescriptionListTerm>MongoDB</DescriptionListTerm>
          <DescriptionListDescription>{srv?.version ?? '—'}</DescriptionListDescription>
        </DescriptionListGroup>
      </DescriptionList>
    </>
  );
}

function Recent() {
  const a = useAuditSearch({ scope: 'self', limit: 6 });
  if (a.isPending) return <Spinner size="md" aria-label="Loading activity" />;
  const ev = a.data?.events ?? [];
  if (ev.length === 0) return <Content component="p">No activity yet.</Content>;
  return (
    <ul className="portal-activity">
      {ev.map((e, i) => (
        <li key={e.id ?? i}>
          <Label isCompact color={e.outcome === 'success' ? 'green' : e.outcome === 'denied' ? 'orange' : 'red'}>
            {e.outcome}
          </Label>{' '}
          <span className="portal-mono">{e.action}</span> {[e.database, e.collection].filter(Boolean).join('.')}{' '}
          <span className="portal-muted portal-small">{new Date(e.time).toLocaleString()}</span>
        </li>
      ))}
    </ul>
  );
}

const quick = [
  { to: '/databases', icon: <ListIcon />, title: 'Databases', text: 'Browse collections and documents' },
  { to: '/shell', icon: <TerminalIcon />, title: 'Shell', text: 'mongosh in your browser' },
  { to: '/transfer', icon: <ExchangeAltIcon />, title: 'Import & export', text: 'JSON, CSV, BSON with field mapping' },
  { to: '/monitoring', icon: <ServerIcon />, title: 'Monitoring', text: 'Members, connections, cache, storage' },
  { to: '/operations', icon: <CubesIcon />, title: 'Operations', text: 'Running operations and idle connections' },
  { to: '/audit', icon: <HistoryIcon />, title: 'Audit', text: 'What happened, by whom' },
];

export function DashboardPage({ me }: { me: Me }) {
  const session = useSession();
  const status = useStatus();
  const s = session.data;
  return (
    <PageSection>
      <Title headingLevel="h1" className="pf-v6-u-mb-md">
        Dashboard
      </Title>
      <Grid hasGutter>
        <GridItem lg={6}>
          <Card isFullHeight>
            <CardTitle>You</CardTitle>
            <CardBody>
              <DescriptionList isCompact isHorizontal>
                <DescriptionListGroup>
                  <DescriptionListTerm>Identity</DescriptionListTerm>
                  <DescriptionListDescription>
                    <IdentityLabel user={me.user} source={me.source} /> <span className="portal-muted">{sourceDescription(me.source)}</span>
                  </DescriptionListDescription>
                </DescriptionListGroup>
                <DescriptionListGroup>
                  <DescriptionListTerm>Portal roles</DescriptionListTerm>
                  <DescriptionListDescription>
                    <RolesLabel roles={me.roles} />
                  </DescriptionListDescription>
                </DescriptionListGroup>
                {s && (
                  <>
                    <DescriptionListGroup>
                      <DescriptionListTerm>MongoDB user</DescriptionListTerm>
                      <DescriptionListDescription className="portal-mono">
                        {s.mongoUser}@{s.authSource} <Label isCompact>{s.mechanism}</Label>
                      </DescriptionListDescription>
                    </DescriptionListGroup>
                    <DescriptionListGroup>
                      <DescriptionListTerm>Connection</DescriptionListTerm>
                      <DescriptionListDescription>
                        {s.profileInfo?.displayName ?? s.profile}{' '}
                        {s.tls ? (
                          <Label isCompact color="green" icon={<LockIcon />}>
                            TLS
                          </Label>
                        ) : (
                          <Label isCompact color="red" icon={<UnlockIcon />}>
                            plaintext
                          </Label>
                        )}
                      </DescriptionListDescription>
                    </DescriptionListGroup>
                  </>
                )}
              </DescriptionList>
            </CardBody>
            <CardFooter>
              <NavLink to="/permissions">
                <ClipboardCheckIcon /> What may I do?
              </NavLink>
            </CardFooter>
          </Card>
        </GridItem>
        <GridItem lg={6}>
          <Card isFullHeight>
            <CardTitle>Deployment health</CardTitle>
            <CardBody>
              <Health me={me} />
              <Flex className="pf-v6-u-mt-md" gap={{ default: 'gapSm' }}>
                {status.data?.profiles.map((p) => (
                  <span key={p.name}>
                    {p.displayName} <HealthLabel h={p.health} />
                  </span>
                ))}
              </Flex>
            </CardBody>
            <CardFooter>
              <NavLink to="/monitoring">Open monitoring</NavLink>
            </CardFooter>
          </Card>
        </GridItem>
        <GridItem span={12}>
          <Grid hasGutter>
            {quick.filter((q) => q.to !== '/transfer' || me.permissions['export:create'] || me.permissions['import:create']).map((q) => (
              <GridItem key={q.to} md={4} xl={2}>
                <Card isCompact isFullHeight>
                  <CardBody>
                    <Button variant="link" isInline component={(props: object) => <NavLink {...props} to={q.to} />} icon={q.icon}>
                      {q.title}
                    </Button>
                    <div className="portal-muted portal-small pf-v6-u-mt-xs">{q.text}</div>
                  </CardBody>
                </Card>
              </GridItem>
            ))}
          </Grid>
        </GridItem>
        <GridItem lg={6}>
          <Card isFullHeight>
            <CardTitle>Your recent activity</CardTitle>
            <CardBody>
              <Recent />
            </CardBody>
            <CardFooter>
              <NavLink to="/audit">All activity</NavLink>
            </CardFooter>
          </Card>
        </GridItem>
        <GridItem lg={6}>
          <Card isFullHeight>
            <CardTitle>Portal</CardTitle>
            <CardBody>
              <DescriptionList isCompact isHorizontal>
                <DescriptionListGroup>
                  <DescriptionListTerm>Audit trail</DescriptionListTerm>
                  <DescriptionListDescription>{status.data?.audit?.persistent ? 'Durable store and log stream' : 'Log stream (this replica keeps recent events)'}</DescriptionListDescription>
                </DescriptionListGroup>
                <DescriptionListGroup>
                  <DescriptionListTerm>Sessions</DescriptionListTerm>
                  <DescriptionListDescription>
                    {status.data?.sessions ? `${status.data.sessions.active} on this replica${status.data.sessions.registry ? ', shared registry' : ''}` : '—'}
                  </DescriptionListDescription>
                </DescriptionListGroup>
                <DescriptionListGroup>
                  <DescriptionListTerm>Tracing</DescriptionListTerm>
                  <DescriptionListDescription>{status.data?.tracing ? 'On' : 'Off'}</DescriptionListDescription>
                </DescriptionListGroup>
              </DescriptionList>
            </CardBody>
            <CardFooter>
              <NavLink to="/status">System status</NavLink>
            </CardFooter>
          </Card>
        </GridItem>
      </Grid>
    </PageSection>
  );
}
