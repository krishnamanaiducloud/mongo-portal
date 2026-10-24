import {
  Alert,
  Card,
  CardBody,
  CardTitle,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Grid,
  GridItem,
  Label,
  PageSection,
  Spinner,
  Title,
} from '@patternfly/react-core';
import { CheckCircleIcon, MinusCircleIcon, OpenshiftIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { useStatus } from '../api/hooks';
import { HealthLabel, OpenShiftStateLabel } from '../components/Indicators';
import { ErrorState } from './StatusPages';

function OnOff({ on, onText = 'Enabled', offText = 'Off' }: { on?: boolean; onText?: string; offText?: string }) {
  return on ? (
    <Label isCompact color="green" icon={<CheckCircleIcon />}>
      {onText}
    </Label>
  ) : (
    <Label isCompact color="grey" icon={<MinusCircleIcon />}>
      {offText}
    </Label>
  );
}

/**
 * Optional integrations are passive: each one shows its state here, and an
 * unavailable integration never stops the portal from working.
 */
export function SystemStatusPage() {
  const st = useStatus();
  if (st.isPending) return <Spinner aria-label="Loading status" />;
  if (st.isError) return <ErrorState error={st.error} onRetry={() => void st.refetch()} />;
  const s = st.data;
  const os = s.auth.openshift;

  return (
    <PageSection>
      <Title headingLevel="h1" className="pf-v6-u-mb-md">
        System status
      </Title>
      <Alert
        variant="info"
        isInline
        isPlain
        className="pf-v6-u-mb-md"
        title="Integrations are optional. When one is unavailable the portal keeps working without it; this page refreshes every 30 seconds."
      />
      <Grid hasGutter>
        <GridItem lg={6}>
          <Card isFullHeight>
            <CardTitle>
              <OpenshiftIcon /> OpenShift sign-in
            </CardTitle>
            <CardBody>
              <DescriptionList isCompact isHorizontal>
                <DescriptionListGroup>
                  <DescriptionListTerm>State</DescriptionListTerm>
                  <DescriptionListDescription>
                    <OpenShiftStateLabel s={os} />
                  </DescriptionListDescription>
                </DescriptionListGroup>
                {os.reason && (
                  <DescriptionListGroup>
                    <DescriptionListTerm>Detail</DescriptionListTerm>
                    <DescriptionListDescription>{os.reason}</DescriptionListDescription>
                  </DescriptionListGroup>
                )}
                {os.issuer && (
                  <DescriptionListGroup>
                    <DescriptionListTerm>OAuth server</DescriptionListTerm>
                    <DescriptionListDescription className="portal-mono">{os.issuer}</DescriptionListDescription>
                  </DescriptionListGroup>
                )}
                {os.checkedAt && (
                  <DescriptionListGroup>
                    <DescriptionListTerm>Last checked</DescriptionListTerm>
                    <DescriptionListDescription>{new Date(os.checkedAt).toLocaleString()}</DescriptionListDescription>
                  </DescriptionListGroup>
                )}
                <DescriptionListGroup>
                  <DescriptionListTerm>MongoDB-only login</DescriptionListTerm>
                  <DescriptionListDescription>
                    <OnOff on={s.auth.mongodbLogin} onText="Allowed" offText="Disabled (SSO required)" />
                  </DescriptionListDescription>
                </DescriptionListGroup>
                {(s.auth.oidc ?? []).map((o) => (
                  <DescriptionListGroup key={o.name}>
                    <DescriptionListTerm>{o.displayName}</DescriptionListTerm>
                    <DescriptionListDescription>
                      <OpenShiftStateLabel s={{ state: o.state, reason: o.reason }} />
                      {o.reason && <div className="portal-muted portal-small">{o.reason}</div>}
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                ))}
                {s.auth.header && (
                  <DescriptionListGroup>
                    <DescriptionListTerm>SSO proxy headers</DescriptionListTerm>
                    <DescriptionListDescription>
                      <OnOff on />
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                )}
              </DescriptionList>
            </CardBody>
          </Card>
        </GridItem>
        <GridItem lg={6}>
          <Card isFullHeight>
            <CardTitle>Portal</CardTitle>
            <CardBody>
              <DescriptionList isCompact isHorizontal>
                {s.rbac && (
                  <DescriptionListGroup>
                    <DescriptionListTerm>RBAC policy</DescriptionListTerm>
                    <DescriptionListDescription>
                      {s.rbac.source === 'file' ? 'RBAC ConfigMap' : s.rbac.source === 'config' ? 'Configuration' : 'Built-in roles'} · default{' '}
                      {s.rbac.defaultRole || 'none'}
                      {s.rbac.error && (
                        <Alert variant="warning" isInline isPlain title="Last update rejected" className="pf-v6-u-mt-xs">
                          {s.rbac.error}
                        </Alert>
                      )}
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                )}
                {s.sessions && (
                  <DescriptionListGroup>
                    <DescriptionListTerm>Sessions on this instance</DescriptionListTerm>
                    <DescriptionListDescription>
                      {s.sessions.active} of {s.sessions.max}
                      {s.pod ? ` · ${s.pod}` : ''}
                      {s.sessions.registry ? ' · shared registry' : ''}
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                )}
                {s.store && (
                  <DescriptionListGroup>
                    <DescriptionListTerm>Shared store</DescriptionListTerm>
                    <DescriptionListDescription>
                      <OnOff on={s.store.state === 'connected'} onText={`Connected${s.store.database ? ` (${s.store.database})` : ''}`} offText={s.store.state === 'disabled' ? 'Not configured' : 'Unavailable'} />
                      {s.store.reason && <div className="portal-muted portal-small">{s.store.reason}</div>}
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                )}
                {s.audit && (
                  <DescriptionListGroup>
                    <DescriptionListTerm>Audit trail</DescriptionListTerm>
                    <DescriptionListDescription>
                      {s.audit.persistent ? `Log stream and store (${s.audit.written} written${s.audit.dropped ? `, ${s.audit.dropped} not persisted` : ''})` : 'Log stream'}
                      {s.audit.lastError && <div className="portal-status-warning portal-small">{s.audit.lastError}</div>}
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                )}
                {s.transfer !== undefined && (
                  <DescriptionListGroup>
                    <DescriptionListTerm>Import &amp; export</DescriptionListTerm>
                    <DescriptionListDescription>
                      <OnOff on={s.transfer} />
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                )}
                {s.shell !== undefined && (
                  <DescriptionListGroup>
                    <DescriptionListTerm>Shell</DescriptionListTerm>
                    <DescriptionListDescription>
                      <OnOff on={s.shell} />
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                )}
                {s.tracing !== undefined && (
                  <DescriptionListGroup>
                    <DescriptionListTerm>Tracing (OTLP)</DescriptionListTerm>
                    <DescriptionListDescription>
                      <OnOff on={s.tracing} offText="Not configured" />
                      {s.tracingDetail?.endpoint && (
                        <div className="portal-muted portal-small">
                          {s.tracingDetail.protocol} · {s.tracingDetail.endpoint} · {s.tracingDetail.tls ? 'TLS' : 'plaintext'} · sampling {Math.round(s.tracingDetail.sampleRatio * 100)}%
                        </div>
                      )}
                      {s.tracingDetail?.reason && !s.tracing && <div className="portal-muted portal-small">{s.tracingDetail.reason}</div>}
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                )}
                <DescriptionListGroup>
                  <DescriptionListTerm>Version</DescriptionListTerm>
                  <DescriptionListDescription className="portal-mono">
                    {s.build.version} ({s.build.commit.slice(0, 12)})
                  </DescriptionListDescription>
                </DescriptionListGroup>
              </DescriptionList>
            </CardBody>
          </Card>
        </GridItem>
        <GridItem span={12}>
          <Card>
            <CardTitle>MongoDB deployments</CardTitle>
            <CardBody>
              <Table aria-label="Connection profiles" variant="compact">
                <Thead>
                  <Tr>
                    <Th>Profile</Th>
                    <Th>Health</Th>
                    <Th>Replica set</Th>
                    <Th>Detail</Th>
                    <Th>Checked</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {s.profiles.map((p) => (
                    <Tr key={p.name}>
                      <Td dataLabel="Profile">{p.displayName}</Td>
                      <Td dataLabel="Health">
                        <HealthLabel h={p.health} />
                      </Td>
                      <Td dataLabel="Replica set">{p.health.setName ?? '—'}</Td>
                      <Td dataLabel="Detail">{p.health.reason ?? ''}</Td>
                      <Td dataLabel="Checked">{p.health.checkedAt ? new Date(p.health.checkedAt).toLocaleTimeString() : '—'}</Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            </CardBody>
          </Card>
        </GridItem>
      </Grid>
    </PageSection>
  );
}
