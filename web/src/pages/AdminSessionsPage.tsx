import { useState } from 'react';
import {
  Alert,
  Button,
  Content,
  Flex,
  Label,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalVariant,
  PageSection,
  SearchInput,
  Spinner,
  Title,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { LockIcon, UnlockIcon } from '@patternfly/react-icons';
import { errorMessage } from '../api/client';
import { useAdminSessions, useRevokeSessions } from '../api/hooks';
import type { SessionMeta } from '../api/types';
import { ErrorState } from './StatusPages';

function ago(iso: string) {
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return `${Math.round(s)} s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  return `${(s / 3600).toFixed(1)} h ago`;
}

type Target = { kind: 'one'; s: SessionMeta } | { kind: 'user'; s: SessionMeta };

export function AdminSessionsPage() {
  const [user, setUser] = useState('');
  const q = useAdminSessions(user);
  const revoke = useRevokeSessions();
  const [target, setTarget] = useState<Target>();
  const data = q.data;
  const confirm = () => {
    if (!target) return;
    revoke.mutate(target.kind === 'one' ? { handle: target.s.handle } : { owner: target.s.owner }, { onSuccess: () => setTarget(undefined) });
  };
  return (
    <PageSection>
      <Flex alignItems={{ default: 'alignItemsCenter' }} className="pf-v6-u-mb-sm">
        <Title headingLevel="h1">Sessions</Title>
        {data && (
          <Label isCompact color={data.source === 'registry' ? 'green' : 'grey'}>
            {data.source === 'registry' ? 'All replicas' : 'This replica'}
          </Label>
        )}
        {q.isFetching && <Spinner size="md" aria-label="Refreshing" />}
      </Flex>
      {data?.note && <Alert variant="info" isInline isPlain className="pf-v6-u-mb-md" title={data.note} />}
      <Content component="p" className="portal-shell-intro pf-v6-u-mb-md">
        Every MongoDB session opened through the portal. Revoking a session disconnects its MongoDB client; the user must connect again.
        Single sign-on itself is ended at the identity provider.
      </Content>
      <Toolbar>
        <ToolbarContent>
          <ToolbarItem>
            <SearchInput aria-label="Filter by user" placeholder="Portal or MongoDB user" value={user} onChange={(_e, v) => setUser(v)} onClear={() => setUser('')} />
          </ToolbarItem>
        </ToolbarContent>
      </Toolbar>
      {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}
      {data && (
        <Table aria-label="Portal sessions" variant="compact">
          <Thead>
            <Tr>
              <Th>User</Th>
              <Th>MongoDB user</Th>
              <Th>Profile</Th>
              <Th>Signed in</Th>
              <Th>Last activity</Th>
              <Th>Client</Th>
              <Th>Replica</Th>
              <Th screenReaderText="Actions" />
            </Tr>
          </Thead>
          <Tbody>
            {data.sessions.map((s) => (
              <Tr key={s.handle}>
                <Td dataLabel="User">
                  {s.user}
                  <div className="portal-muted portal-small">
                    {s.identity}
                    {s.provider ? ` · ${s.provider}` : ''}
                  </div>
                  {s.current && (
                    <Label isCompact color="blue">
                      you, this browser
                    </Label>
                  )}
                </Td>
                <Td dataLabel="MongoDB user" className="portal-mono">
                  {s.mongoUser}@{s.authSource}
                  <div className="portal-muted portal-small">{s.mechanism}</div>
                </Td>
                <Td dataLabel="Profile">
                  {s.profile}{' '}
                  {s.tls ? <LockIcon aria-label="TLS" className="portal-status-success" /> : <UnlockIcon aria-label="Plaintext" className="portal-status-warning" />}
                </Td>
                <Td dataLabel="Signed in">{new Date(s.createdAt).toLocaleString()}</Td>
                <Td dataLabel="Last activity">{ago(s.lastSeen)}</Td>
                <Td dataLabel="Client">
                  <span className="portal-mono">{s.clientIP || '—'}</span>
                  {s.userAgent && <div className="portal-muted portal-small portal-ellipsis">{s.userAgent}</div>}
                </Td>
                <Td dataLabel="Replica" className="portal-mono">
                  {s.pod}
                </Td>
                <Td dataLabel="Actions" isActionCell>
                  {data.canRevoke && (
                    <Flex gap={{ default: 'gapSm' }} flexWrap={{ default: 'nowrap' }}>
                      <Button variant="secondary" size="sm" isDanger onClick={() => setTarget({ kind: 'one', s })}>
                        Revoke
                      </Button>
                      <Button variant="link" size="sm" isDanger onClick={() => setTarget({ kind: 'user', s })}>
                        All of this user
                      </Button>
                    </Flex>
                  )}
                </Td>
              </Tr>
            ))}
            {data.sessions.length === 0 && (
              <Tr>
                <Td colSpan={8}>No sessions.</Td>
              </Tr>
            )}
          </Tbody>
        </Table>
      )}
      {target && (
        <Modal variant={ModalVariant.small} isOpen onClose={() => setTarget(undefined)} aria-labelledby="revoke-title">
          <ModalHeader title={target.kind === 'one' ? 'Revoke this session?' : `Revoke every session of ${target.s.user}?`} labelId="revoke-title" titleIconVariant="warning" />
          <ModalBody>
            <Content component="p">
              {target.kind === 'one'
                ? `The MongoDB session of ${target.s.user} (${target.s.mongoUser}) on ${target.s.profile} is closed.`
                : `All MongoDB sessions of ${target.s.user} on every replica are closed. They can sign in again unless their access is removed.`}{' '}
              Replicas close revoked sessions within the registry sync interval. The action is audited.
            </Content>
            {revoke.error && <Alert variant="danger" isInline title={errorMessage(revoke.error)} />}
          </ModalBody>
          <ModalFooter>
            <Button variant="danger" onClick={confirm} isLoading={revoke.isPending} isDisabled={revoke.isPending}>
              Revoke
            </Button>
            <Button variant="link" onClick={() => setTarget(undefined)}>
              Cancel
            </Button>
          </ModalFooter>
        </Modal>
      )}
    </PageSection>
  );
}
