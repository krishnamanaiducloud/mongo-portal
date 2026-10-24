import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router';
import {
  Alert,
  Button,
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
  LabelGroup,
  PageSection,
  Title,
} from '@patternfly/react-core';
import { LockIcon, UnlockIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { useLogout, useSession, useSessions, useTerminateSession } from '../api/hooks';
import type { Me } from '../api/types';
import { IdentityLabel, sourceDescription } from '../components/Indicators';
import { RolesLabel } from '../components/Permission';
import { InlineError } from './StatusPages';

function useNow(intervalMs: number) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}

function remaining(iso: string, now: number): string {
  const s = Math.max(0, Math.floor((Date.parse(iso) - now) / 1000));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return h > 0 ? `${h}h ${m}m` : `${m}m ${s % 60}s`;
}

export function SessionPage({ me }: { me: Me }) {
  const session = useSession();
  const sessions = useSessions();
  const terminate = useTerminateSession();
  const logout = useLogout();
  const navigate = useNavigate();
  const now = useNow(1000);
  const s = session.data;
  const id = s?.identity ?? { user: me.user, source: me.source, groups: me.groups };

  const doLogout = async () => {
    try {
      await logout.mutateAsync();
    } finally {
      navigate('/login?reason=logout', { replace: true });
    }
  };

  return (
    <PageSection>
      <Title headingLevel="h1" className="pf-v6-u-mb-md">
        Session &amp; security
      </Title>
      <Grid hasGutter>
        <GridItem lg={6}>
          <Card isFullHeight>
            <CardTitle>Identity &amp; portal access</CardTitle>
            <CardBody>
              <DescriptionList isHorizontal>
                <DescriptionListGroup>
                  <DescriptionListTerm>User</DescriptionListTerm>
                  <DescriptionListDescription>
                    <IdentityLabel user={id.user} source={id.source} />
                    <div className="pf-v6-u-font-size-sm">{sourceDescription(id.source)}</div>
                  </DescriptionListDescription>
                </DescriptionListGroup>
                <DescriptionListGroup>
                  <DescriptionListTerm>Portal roles</DescriptionListTerm>
                  <DescriptionListDescription>
                    <RolesLabel roles={s?.portalRoles ?? me.roles} />
                  </DescriptionListDescription>
                </DescriptionListGroup>
                {(id.groups ?? []).length > 0 && (
                  <DescriptionListGroup>
                    <DescriptionListTerm>Groups used by RBAC</DescriptionListTerm>
                    <DescriptionListDescription>
                      <LabelGroup>{(id.groups ?? []).map((g) => <Label key={g} isCompact>{g}</Label>)}</LabelGroup>
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                )}
              </DescriptionList>
            </CardBody>
          </Card>
        </GridItem>
        <GridItem lg={6}>
          <Card isFullHeight>
            <CardTitle>MongoDB session</CardTitle>
            <CardBody>
              {s && (
                <DescriptionList isHorizontal>
                  <DescriptionListGroup>
                    <DescriptionListTerm>MongoDB user</DescriptionListTerm>
                    <DescriptionListDescription>
                      {s.mongoUser}@{s.authSource} ({s.mechanism || 'negotiated'})
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                  <DescriptionListGroup>
                    <DescriptionListTerm>Connection profile</DescriptionListTerm>
                    <DescriptionListDescription>{s.profileInfo?.displayName ?? s.profile}</DescriptionListDescription>
                  </DescriptionListGroup>
                  <DescriptionListGroup>
                    <DescriptionListTerm>Transport</DescriptionListTerm>
                    <DescriptionListDescription>
                      {s.tls ? (
                        <Label color="green" icon={<LockIcon />}>TLS (certificate verified)</Label>
                      ) : (
                        <Label color="red" icon={<UnlockIcon />}>Plaintext — not encrypted</Label>
                      )}
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                  <DescriptionListGroup>
                    <DescriptionListTerm>MongoDB roles</DescriptionListTerm>
                    <DescriptionListDescription>
                      <LabelGroup numLabels={8}>
                        {(s.mongoRoles ?? []).map((r) => (
                          <Label key={`${r.role}@${r.db}`} isCompact>
                            {r.role}@{r.db}
                          </Label>
                        ))}
                      </LabelGroup>
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                  <DescriptionListGroup>
                    <DescriptionListTerm>Idle timeout</DescriptionListTerm>
                    <DescriptionListDescription>
                      {Math.round(s.idleTimeoutSeconds / 60)} min of inactivity
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                  <DescriptionListGroup>
                    <DescriptionListTerm>Session ends</DescriptionListTerm>
                    <DescriptionListDescription>
                      in {remaining(s.expiresAt, now)} (absolute limit)
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                </DescriptionList>
              )}
              <Button variant="secondary" className="pf-v6-u-mt-md" onClick={() => void doLogout()} isLoading={logout.isPending}>
                Disconnect from MongoDB
              </Button>
              {me.ssoLogoutURL && id.source === 'openshift' && (
                <Button variant="link" component="a" href={me.ssoLogoutURL} className="pf-v6-u-mt-md">
                  Sign out at the identity provider
                </Button>
              )}
            </CardBody>
          </Card>
        </GridItem>
        <GridItem span={12}>
          <Card>
            <CardTitle>Your active sessions</CardTitle>
            <CardBody>
              {sessions.data?.note && <Alert variant="info" isInline isPlain title={sessions.data.note} className="pf-v6-u-mb-sm" />}
              <InlineError error={sessions.error ?? terminate.error} />
              <Table aria-label="Active sessions" variant="compact">
                <Thead>
                  <Tr>
                    <Th>MongoDB user</Th>
                    <Th>Profile</Th>
                    <Th>Started</Th>
                    <Th>Last activity</Th>
                    <Th>Client</Th>
                    <Th screenReaderText="Actions" />
                  </Tr>
                </Thead>
                <Tbody>
                  {(sessions.data?.sessions ?? []).map((x) => (
                    <Tr key={x.handle}>
                      <Td dataLabel="MongoDB user">
                        {x.mongoUser}@{x.authSource} {x.current && <Label isCompact color="green">this session</Label>}
                      </Td>
                      <Td dataLabel="Profile">{x.profile}</Td>
                      <Td dataLabel="Started">{new Date(x.createdAt).toLocaleString()}</Td>
                      <Td dataLabel="Last activity">{new Date(x.lastSeen).toLocaleString()}</Td>
                      <Td dataLabel="Client" modifier="truncate">{x.userAgent}</Td>
                      <Td isActionCell>
                        {!x.current && (
                          <Button variant="link" isDanger onClick={() => terminate.mutate(x.handle)}>
                            Terminate
                          </Button>
                        )}
                      </Td>
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
