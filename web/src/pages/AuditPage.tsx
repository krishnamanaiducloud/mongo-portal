import { useState } from 'react';
import {
  Alert,
  AlertActionCloseButton,
  Button,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Flex,
  FormSelect,
  FormSelectOption,
  Label,
  PageSection,
  SearchInput,
  Spinner,
  Switch,
  TextInput,
  Title,
  Toolbar,
  ToolbarContent,
  ToolbarGroup,
  ToolbarItem,
} from '@patternfly/react-core';
import { ExpandableRowContent, Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { CheckCircleIcon, DownloadIcon, ExclamationCircleIcon } from '@patternfly/react-icons';
import { auditQueryString, useAuditSearch, useAuditVerify } from '../api/hooks';
import type { AuditEvent, AuditQuery, Me } from '../api/types';
import { ErrorState } from './StatusPages';

const outcomeColor = { success: 'green', denied: 'orange', failure: 'red' } as const;

const actions = [
  'sso_login', 'mongodb_login', 'mongodb_logout', 'sign_out', 'session_closed', 'session_terminate', 'session_revoke', 'rbac_denied',
  'insert_document', 'replace_document', 'delete_document', 'create_collection', 'drop_collection', 'drop_database', 'create_index',
  'drop_index', 'query', 'shell', 'export', 'export_database', 'import', 'import_dry_run', 'import_cancel', 'operation_kill', 'audit_export',
];

// datetime-local values are local time; the API wants RFC 3339.
function toRFC3339(v: string) {
  if (!v) return undefined;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

function Details({ e }: { e: AuditEvent }) {
  const rows: [string, string | number | undefined][] = [
    ['Event id', e.id], ['Request id', e.requestId], ['Trace id', e.traceId], ['Identity', [e.identity, e.provider].filter(Boolean).join(' / ')],
    ['Portal roles', e.portalRole], ['Method', e.method], ['Profile', e.profile], ['Target', e.target], ['Reason', e.reason],
    ['Error class', e.errorClass], ['Duration', e.durationMs !== undefined ? `${e.durationMs} ms` : undefined], ['Documents', e.count],
    ['Client', e.client], ['Session', e.session], ['Replica', e.pod], ['Sequence', e.seq], ['Chain hash', e.hash],
  ];
  return (
    <DescriptionList isCompact isHorizontal columnModifier={{ default: '2Col' }}>
      {rows
        .filter(([, v]) => v !== undefined && v !== '')
        .map(([k, v]) => (
          <DescriptionListGroup key={k}>
            <DescriptionListTerm>{k}</DescriptionListTerm>
            <DescriptionListDescription className={k.endsWith('id') || k === 'Chain hash' ? 'portal-mono' : undefined}>{v}</DescriptionListDescription>
          </DescriptionListGroup>
        ))}
    </DescriptionList>
  );
}

export function AuditPage({ me }: { me: Me }) {
  const canAll = !!me.permissions['audit:all'];
  const [f, setF] = useState<AuditQuery>({ scope: 'self', limit: 100 });
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [pages, setPages] = useState<{ before: string; beforeId: string }[]>([]);
  const [open, setOpen] = useState<string>();
  const [verifyPod, setVerifyPod] = useState<string>();
  const query: AuditQuery = { ...f, from: toRFC3339(from), to: toRFC3339(to) };
  const cursor = pages[pages.length - 1];
  const audit = useAuditSearch(query, cursor);
  const verify = useAuditVerify(verifyPod);
  const upd = (p: Partial<AuditQuery>) => {
    setPages([]);
    setF((x) => ({ ...x, ...p }));
  };
  const exportURL = (format: 'csv' | 'ndjson') => `/api/v1/audit${auditQueryString(query, { format })}`;
  const data = audit.data;

  return (
    <PageSection>
      <Flex alignItems={{ default: 'alignItemsCenter' }} className="pf-v6-u-mb-sm">
        <Title headingLevel="h1">Audit</Title>
        {data && (
          <Label color={data.durable ? 'green' : 'grey'} isCompact>
            {data.durable ? 'Durable store, every replica' : 'This replica only'}
          </Label>
        )}
        {audit.isFetching && <Spinner size="md" aria-label="Loading" />}
      </Flex>
      {data?.note && <Alert variant="info" isInline isPlain title={data.note} className="pf-v6-u-mb-md" />}
      <Toolbar>
        <ToolbarContent>
          {canAll && (
            <ToolbarItem>
              <Switch id="audit-all" label="All users" isChecked={f.scope === 'all'} onChange={(_e, v) => upd({ scope: v ? 'all' : 'self' })} />
            </ToolbarItem>
          )}
          <ToolbarItem>
            <SearchInput aria-label="User" placeholder="User" value={f.user ?? ''} onChange={(_e, v) => upd({ user: v || undefined })} onClear={() => upd({ user: undefined })} />
          </ToolbarItem>
          <ToolbarItem>
            <FormSelect aria-label="Action" value={f.action ?? ''} onChange={(_e, v) => upd({ action: v || undefined })}>
              <FormSelectOption value="" label="Any action" />
              {actions.map((a) => (
                <FormSelectOption key={a} value={a} label={a} />
              ))}
            </FormSelect>
          </ToolbarItem>
          <ToolbarItem>
            <FormSelect aria-label="Outcome" value={f.outcome ?? ''} onChange={(_e, v) => upd({ outcome: v || undefined })}>
              <FormSelectOption value="" label="Any outcome" />
              <FormSelectOption value="success" label="Success" />
              <FormSelectOption value="denied" label="Denied" />
              <FormSelectOption value="failure" label="Failure" />
            </FormSelect>
          </ToolbarItem>
          <ToolbarItem>
            <SearchInput aria-label="Database" placeholder="Database" value={f.database ?? ''} onChange={(_e, v) => upd({ database: v || undefined })} onClear={() => upd({ database: undefined })} />
          </ToolbarItem>
          <ToolbarItem>
            <SearchInput aria-label="Text" placeholder="Target or reason" value={f.q ?? ''} onChange={(_e, v) => upd({ q: v || undefined })} onClear={() => upd({ q: undefined })} />
          </ToolbarItem>
          <ToolbarGroup>
            <ToolbarItem>
              <TextInput type="datetime-local" aria-label="From" value={from} onChange={(_e, v) => { setPages([]); setFrom(v); }} />
            </ToolbarItem>
            <ToolbarItem>
              <TextInput type="datetime-local" aria-label="To" value={to} onChange={(_e, v) => { setPages([]); setTo(v); }} />
            </ToolbarItem>
          </ToolbarGroup>
          <ToolbarGroup align={{ default: 'alignEnd' }}>
            <ToolbarItem>
              <Button variant="secondary" component="a" href={exportURL('csv')} download icon={<DownloadIcon />}>
                CSV
              </Button>
            </ToolbarItem>
            <ToolbarItem>
              <Button variant="secondary" component="a" href={exportURL('ndjson')} download icon={<DownloadIcon />}>
                NDJSON
              </Button>
            </ToolbarItem>
          </ToolbarGroup>
        </ToolbarContent>
      </Toolbar>
      {audit.isError && !data && <ErrorState error={audit.error} onRetry={() => void audit.refetch()} />}
      {data && (
        <Table aria-label="Audit events" variant="compact">
          <Thead>
            <Tr>
              <Th screenReaderText="Details" />
              <Th>Time</Th>
              <Th>User</Th>
              <Th>MongoDB user</Th>
              <Th>Action</Th>
              <Th>Namespace</Th>
              <Th>Outcome</Th>
            </Tr>
          </Thead>
          {data.events.map((e, i) => {
            const key = e.id ?? `${e.time}-${i}`;
            const isOpen = open === key;
            return (
              <Tbody key={key} isExpanded={isOpen}>
                <Tr>
                  <Td expand={{ rowIndex: i, isExpanded: isOpen, onToggle: () => setOpen(isOpen ? undefined : key) }} />
                  <Td dataLabel="Time">{new Date(e.time).toLocaleString()}</Td>
                  <Td dataLabel="User">
                    {e.ssoUser}
                    {e.identity && e.identity !== 'mongodb' && <span className="portal-muted portal-small"> ({e.identity})</span>}
                  </Td>
                  <Td dataLabel="MongoDB user">{e.mongoUser}</Td>
                  <Td dataLabel="Action" className="portal-mono">
                    {e.action}
                  </Td>
                  <Td dataLabel="Namespace">{[e.database, e.collection].filter(Boolean).join('.')}</Td>
                  <Td dataLabel="Outcome">
                    <Label isCompact color={outcomeColor[e.outcome]}>
                      {e.outcome}
                    </Label>{' '}
                    {e.reason && <span className="portal-small">{e.reason}</span>}
                  </Td>
                </Tr>
                <Tr isExpanded={isOpen}>
                  <Td colSpan={7}>
                    <ExpandableRowContent>
                      <Details e={e} />
                      {canAll && e.pod && data.durable && (
                        <Button variant="link" isInline className="pf-v6-u-mt-sm" onClick={() => setVerifyPod(e.pod)}>
                          Verify the hash chain of {e.pod}
                        </Button>
                      )}
                    </ExpandableRowContent>
                  </Td>
                </Tr>
              </Tbody>
            );
          })}
          {data.events.length === 0 && (
            <Tbody>
              <Tr>
                <Td colSpan={7}>No events match.</Td>
              </Tr>
            </Tbody>
          )}
        </Table>
      )}
      <Flex className="pf-v6-u-mt-md" gap={{ default: 'gapSm' }}>
        {pages.length > 0 && (
          <Button variant="secondary" onClick={() => setPages((p) => p.slice(0, -1))}>
            Newer
          </Button>
        )}
        {data?.next && (
          <Button variant="secondary" onClick={() => setPages((p) => [...p, data.next!])}>
            Older
          </Button>
        )}
      </Flex>
      {verifyPod && (
        <Alert
          className="pf-v6-u-mt-md"
          isInline
          variant={verify.data ? (verify.data.intact ? 'success' : 'danger') : verify.isError ? 'warning' : 'info'}
          title={
            verify.isPending
              ? `Verifying ${verifyPod}…`
              : verify.isError
                ? 'Verification is not available'
                : verify.data?.intact
                  ? `Chain intact: ${verify.data.checked} events of ${verifyPod} (sequence ${verify.data.firstSeq}–${verify.data.lastSeq})`
                  : `Chain broken at sequence ${verify.data?.brokenAtSeq} of ${verifyPod}`
          }
          customIcon={verify.data ? verify.data.intact ? <CheckCircleIcon /> : <ExclamationCircleIcon /> : undefined}
          actionClose={<AlertActionCloseButton onClose={() => setVerifyPod(undefined)} />}
        >
          {verify.data && !verify.data.intact && 'An event was removed, inserted or altered after it was written. Investigate the audit store.'}
          {verify.data?.intact && 'Gaps at the start are expected when retention removed older events or the replica restarted.'}
        </Alert>
      )}
    </PageSection>
  );
}
