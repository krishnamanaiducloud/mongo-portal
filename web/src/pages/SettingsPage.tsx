import { Card, CardBody, CardTitle, Content, Gallery, Label, PageSection, Spinner, Title } from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { LockIcon, UnlockIcon } from '@patternfly/react-icons';
import { useSettings } from '../api/hooks';
import { DocumentView } from '../components/DocumentView';
import { ErrorState } from './StatusPages';

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj => (v && typeof v === 'object' ? (v as Obj) : {});
const arr = (v: unknown): Obj[] => (Array.isArray(v) ? (v as Obj[]) : []);

function StateLabel({ s }: { s: unknown }) {
  const st = obj(s);
  const state = String(st.state ?? 'unknown');
  const color = state === 'available' || state === 'connected' || state === 'online' ? 'green' : state === 'disabled' ? 'grey' : 'orange';
  return (
    <Label isCompact color={color} title={st.reason ? String(st.reason) : undefined}>
      {state}
    </Label>
  );
}

export function SettingsPage() {
  const q = useSettings();
  if (q.isPending) return <PageSection><Spinner aria-label="Loading settings" /></PageSection>;
  if (q.isError) return <PageSection><ErrorState error={q.error} onRetry={() => void q.refetch()} /></PageSection>;
  const s = q.data;
  const id = obj(s.identity);
  const sections = ['rbac', 'session', 'audit', 'store', 'transfer', 'shell', 'query', 'monitoring', 'tracing'];
  return (
    <PageSection>
      <Title headingLevel="h1" className="pf-v6-u-mb-sm">
        Settings
      </Title>
      <Content component="p" className="portal-shell-intro pf-v6-u-mb-md">
        The effective configuration of this replica ({String(s.pod ?? '')}, environment {String(s.environment || '—')}). It is read-only here:
        change it in the configuration ConfigMap and RBAC policy. Secrets are never shown, only whether they are configured.
      </Content>
      <Card className="pf-v6-u-mb-md">
        <CardTitle>Sign-in</CardTitle>
        <CardBody>
          <Content component="p">
            OpenShift: <StateLabel s={obj(id.openshift).status} /> · trusted proxy headers: {id.header ? 'on' : 'off'} · single sign-on required:{' '}
            {id.requireSSO ? 'yes' : 'no'}
          </Content>
          <Table aria-label="OpenID Connect providers" variant="compact">
            <Thead>
              <Tr>
                <Th>Provider</Th>
                <Th>Issuer</Th>
                <Th>Client</Th>
                <Th>Claims</Th>
                <Th>State</Th>
              </Tr>
            </Thead>
            <Tbody>
              {arr(id.oidc).map((p) => (
                <Tr key={String(p.name)}>
                  <Td dataLabel="Provider">
                    {String(p.displayName)} <span className="portal-muted">({String(p.name)})</span>
                  </Td>
                  <Td dataLabel="Issuer" className="portal-mono">
                    {String(p.issuer)}
                  </Td>
                  <Td dataLabel="Client" className="portal-mono">
                    {String(p.clientID)}
                    {p.confidentialClient ? ' · secret' : ' · public + PKCE'}
                  </Td>
                  <Td dataLabel="Claims">
                    user: {String(p.usernameClaim)}, groups: {String(p.groupsClaim)}
                  </Td>
                  <Td dataLabel="State">
                    <StateLabel s={p.status} />
                  </Td>
                </Tr>
              ))}
              {arr(id.oidc).length === 0 && (
                <Tr>
                  <Td colSpan={5}>No OpenID Connect providers are configured.</Td>
                </Tr>
              )}
            </Tbody>
          </Table>
        </CardBody>
      </Card>
      <Card className="pf-v6-u-mb-md">
        <CardTitle>Connection profiles</CardTitle>
        <CardBody>
          <Table aria-label="Connection profiles" variant="compact">
            <Thead>
              <Tr>
                <Th>Profile</Th>
                <Th>Hosts</Th>
                <Th>Authentication</Th>
                <Th>Transport</Th>
                <Th>Health</Th>
              </Tr>
            </Thead>
            <Tbody>
              {arr(s.profiles).map((p) => {
                const tls = obj(p.tls);
                const oidc = obj(p.oidc);
                return (
                  <Tr key={String(p.name)}>
                    <Td dataLabel="Profile">
                      {String(p.displayName)}
                      {p.replicaSet ? <div className="portal-muted portal-small">rs {String(p.replicaSet)}</div> : null}
                    </Td>
                    <Td dataLabel="Hosts" className="portal-mono">
                      {(p.hosts as string[] | undefined)?.join(', ')}
                    </Td>
                    <Td dataLabel="Authentication">
                      {(p.authMechanisms as string[] | undefined)?.join(', ')}
                      {oidc.issuer ? <div className="portal-muted portal-small">OIDC: {String(oidc.issuer)} ({String(oidc.clientID)})</div> : null}
                    </Td>
                    <Td dataLabel="Transport">
                      {tls.mode === 'enabled' ? (
                        <Label isCompact color="green" icon={<LockIcon />}>
                          TLS {String(tls.minVersion)}+{tls.customCA ? ', custom CA' : ''}
                          {tls.clientCertificate ? ', client cert' : ''}
                        </Label>
                      ) : (
                        <Label isCompact color="red" icon={<UnlockIcon />}>
                          plaintext{p.plaintextApproved ? ' (approved exception)' : ''}
                        </Label>
                      )}
                    </Td>
                    <Td dataLabel="Health">
                      <StateLabel s={p.health} />
                    </Td>
                  </Tr>
                );
              })}
            </Tbody>
          </Table>
        </CardBody>
      </Card>
      <Gallery hasGutter minWidths={{ default: '320px' }}>
        {sections.map((k) => (
          <Card key={k} isCompact>
            <CardTitle className="portal-capitalize">{k}</CardTitle>
            <CardBody>
              <DocumentView doc={obj(s[k])} expandDepth={2} />
            </CardBody>
          </Card>
        ))}
      </Gallery>
    </PageSection>
  );
}
