import { useState } from 'react';
import { Alert, Label, PageSection, Spinner, Switch, Title, Toolbar, ToolbarContent, ToolbarItem } from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { useAudit } from '../api/hooks';
import type { Me } from '../api/types';
import { ErrorState } from './StatusPages';

const outcomeColor = { success: 'green', denied: 'orange', failure: 'red' } as const;

export function AuditPage({ me }: { me: Me }) {
  const [all, setAll] = useState(false);
  const audit = useAudit(all ? 'all' : 'self');
  return (
    <PageSection>
      <Title headingLevel="h1" className="pf-v6-u-mb-md">
        Audit activity
      </Title>
      {audit.data?.note && <Alert variant="info" isInline isPlain title={audit.data.note} className="pf-v6-u-mb-md" />}
      {me.permissions['audit:all'] && (
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <Switch id="audit-all" label="Show all users" isChecked={all} onChange={(_e, v) => setAll(v)} />
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
      )}
      {audit.isPending && <Spinner aria-label="Loading audit events" />}
      {audit.isError && <ErrorState error={audit.error} onRetry={() => void audit.refetch()} />}
      {audit.data && (
        <Table aria-label="Audit events" variant="compact">
          <Thead>
            <Tr>
              <Th>Time</Th>
              <Th>User</Th>
              <Th>MongoDB user</Th>
              <Th>Action</Th>
              <Th>Namespace</Th>
              <Th>Outcome</Th>
            </Tr>
          </Thead>
          <Tbody>
            {audit.data.events.map((e, i) => (
              <Tr key={`${e.time}-${i}`}>
                <Td dataLabel="Time">{new Date(e.time).toLocaleString()}</Td>
                <Td dataLabel="User">
                  {e.ssoUser}
                  {e.identity && e.identity !== 'mongodb' && <span className="pf-v6-u-font-size-sm"> ({e.identity})</span>}
                </Td>
                <Td dataLabel="MongoDB user">{e.mongoUser}</Td>
                <Td dataLabel="Action" className="portal-mono">{e.action}</Td>
                <Td dataLabel="Namespace">
                  {[e.database, e.collection].filter(Boolean).join('.')}
                  {e.target ? ` (${e.target})` : ''}
                </Td>
                <Td dataLabel="Outcome">
                  <Label isCompact color={outcomeColor[e.outcome]} title={e.reason}>
                    {e.outcome}
                  </Label>{' '}
                  {e.reason && <span className="pf-v6-u-font-size-sm">{e.reason}</span>}
                </Td>
              </Tr>
            ))}
            {audit.data.events.length === 0 && (
              <Tr>
                <Td colSpan={6}>No events recorded yet.</Td>
              </Tr>
            )}
          </Tbody>
        </Table>
      )}
    </PageSection>
  );
}
