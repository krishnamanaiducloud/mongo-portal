import { useState } from 'react';
import {
  Alert,
  Button,
  Checkbox,
  Content,
  Flex,
  FormSelect,
  FormSelectOption,
  Label,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalVariant,
  PageSection,
  Pagination,
  SearchInput,
  Spinner,
  TextInput,
  Title,
  ToggleGroup,
  ToggleGroupItem,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
  Tooltip,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { ExclamationTriangleIcon, SyncAltIcon } from '@patternfly/react-icons';
import { errorMessage } from '../api/client';
import { type OperationFilter, useKillOperation, useOperations } from '../api/hooks';
import type { Operation } from '../api/types';
import { ErrorState } from './StatusPages';

function fmtSecs(s: number) {
  if (s < 1) return `${Math.round(s * 1000)} ms`;
  if (s < 120) return `${s.toFixed(1)} s`;
  if (s < 7200) return `${Math.floor(s / 60)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}

function KillModal({ op, onClose }: { op: Operation; onClose: () => void }) {
  const kill = useKillOperation();
  const [typed, setTyped] = useState('');
  const id = String(op.opid);
  return (
    <Modal variant={ModalVariant.small} isOpen onClose={onClose} aria-labelledby="kill-title">
      <ModalHeader title="End this operation?" labelId="kill-title" titleIconVariant="warning" />
      <ModalBody>
        <Content component="p">
          <strong>{op.op}</strong> on <span className="portal-mono">{op.ns || '—'}</span>, running for {fmtSecs(op.secsRunning)}, from{' '}
          <span className="portal-mono">{op.client}</span>
          {op.appName ? ` (${op.appName})` : ''}
          {op.user ? `, user ${op.user}` : ''}.
        </Content>
        <Content component="p">
          killOp asks MongoDB to stop the operation at its next interruption point. The client receives an error; writes already applied
          stay applied, and the connection stays open. MongoDB requires the killop privilege for other users&apos; operations.
        </Content>
        <TextInput aria-label="Operation id to confirm" placeholder={`Type ${id} to confirm`} value={typed} onChange={(_e, v) => setTyped(v)} autoFocus />
        {kill.error && <Alert className="pf-v6-u-mt-md" variant="danger" isInline title={errorMessage(kill.error)} />}
        {kill.data && <Alert className="pf-v6-u-mt-md" variant="success" isInline title={kill.data.note} />}
      </ModalBody>
      <ModalFooter>
        <Button variant="danger" isDisabled={typed !== id || kill.isPending || !!kill.data} isLoading={kill.isPending} onClick={() => kill.mutate(op.opid)}>
          End operation {id}
        </Button>
        <Button variant="link" onClick={onClose}>
          {kill.data ? 'Close' : 'Cancel'}
        </Button>
      </ModalFooter>
    </Modal>
  );
}

export function OperationsPage() {
  const [f, setF] = useState<OperationFilter>({ state: 'active', limit: 50, offset: 0 });
  const [auto, setAuto] = useState(true);
  const [target, setTarget] = useState<Operation>();
  const q = useOperations(f, auto ? 5000 : false);
  const upd = (p: Partial<OperationFilter>) => setF((x) => ({ ...x, offset: 0, ...p }));
  const data = q.data;
  const page = Math.floor((f.offset ?? 0) / (f.limit ?? 50)) + 1;
  return (
    <PageSection>
      <Flex alignItems={{ default: 'alignItemsCenter' }} className="pf-v6-u-mb-sm">
        <Title headingLevel="h1">Operations &amp; connections</Title>
        {q.isFetching && <Spinner size="md" aria-label="Refreshing" />}
      </Flex>
      <Content component="p" className="portal-shell-intro pf-v6-u-mb-md">
        What the MongoDB member is doing right now, from <code>$currentOp</code> with your own session. Only metadata is shown, never query
        texts or documents.
      </Content>
      <Toolbar>
        <ToolbarContent>
          <ToolbarItem>
            <ToggleGroup aria-label="Operation state">
              {(['active', 'idle', 'all'] as const).map((s) => (
                <ToggleGroupItem key={s} text={s === 'active' ? 'Running' : s === 'idle' ? 'Idle connections' : 'All'} isSelected={f.state === s} onChange={() => upd({ state: s })} />
              ))}
            </ToggleGroup>
          </ToolbarItem>
          <ToolbarItem>
            <SearchInput aria-label="Client host" placeholder="Client" value={f.client ?? ''} onChange={(_e, v) => upd({ client: v || undefined })} onClear={() => upd({ client: undefined })} />
          </ToolbarItem>
          <ToolbarItem>
            <SearchInput aria-label="Application" placeholder="Application" value={f.app ?? ''} onChange={(_e, v) => upd({ app: v || undefined })} onClear={() => upd({ app: undefined })} />
          </ToolbarItem>
          <ToolbarItem>
            <SearchInput aria-label="User" placeholder="User" value={f.user ?? ''} onChange={(_e, v) => upd({ user: v || undefined })} onClear={() => upd({ user: undefined })} />
          </ToolbarItem>
          <ToolbarItem>
            <SearchInput aria-label="Namespace" placeholder="Namespace" value={f.ns ?? ''} onChange={(_e, v) => upd({ ns: v || undefined })} onClear={() => upd({ ns: undefined })} />
          </ToolbarItem>
          <ToolbarItem>
            <FormSelect aria-label="Minimum duration" value={String(f.minSecs ?? '')} onChange={(_e, v) => upd({ minSecs: v ? Number(v) : undefined })}>
              <FormSelectOption value="" label="Any duration" />
              <FormSelectOption value="1" label="≥ 1 s" />
              <FormSelectOption value="5" label="≥ 5 s" />
              <FormSelectOption value="30" label="≥ 30 s" />
              <FormSelectOption value="300" label="≥ 5 min" />
            </FormSelect>
          </ToolbarItem>
          <ToolbarItem>
            <Checkbox id="op-internal" label="Internal threads" isChecked={!!f.internal} onChange={(_e, v) => upd({ internal: v || undefined })} />
          </ToolbarItem>
          <ToolbarItem>
            <Checkbox id="op-auto" label="Refresh every 5 s" isChecked={auto} onChange={(_e, v) => setAuto(v)} />
          </ToolbarItem>
          <ToolbarItem>
            <Button variant="plain" aria-label="Refresh now" icon={<SyncAltIcon />} onClick={() => void q.refetch()} />
          </ToolbarItem>
        </ToolbarContent>
      </Toolbar>
      {data?.note && <Alert variant="info" isInline isPlain className="pf-v6-u-mb-sm" title={data.note} />}
      {q.isError && !data && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}
      {data && (
        <>
          <Table aria-label="Operations" variant="compact">
            <Thead>
              <Tr>
                <Th>Operation</Th>
                <Th>Namespace</Th>
                <Th>Running</Th>
                <Th>Client</Th>
                <Th>User</Th>
                <Th>Plan</Th>
                <Th screenReaderText="Actions" />
              </Tr>
            </Thead>
            <Tbody>
              {data.operations.map((o, i) => (
                <Tr key={`${String(o.opid)}-${i}`}>
                  <Td dataLabel="Operation">
                    <span className="portal-mono">{o.op || (o.active ? o.type : 'idle')}</span>
                    {o.slow && (
                      <Label isCompact color="orange" icon={<ExclamationTriangleIcon />} className="pf-v6-u-ml-sm">
                        slow
                      </Label>
                    )}
                    {o.expectedWait && (
                      <Tooltip content={`${o.expectedWait}. This is normal and not counted as slow.`}>
                        <Label isCompact color="teal" className="pf-v6-u-ml-sm">
                          expected wait
                        </Label>
                      </Tooltip>
                    )}
                    {o.waitingForLock && (
                      <Label isCompact color="orange" className="pf-v6-u-ml-sm">
                        waiting for lock
                      </Label>
                    )}
                    {o.killPending && (
                      <Label isCompact className="pf-v6-u-ml-sm">
                        ending
                      </Label>
                    )}
                    {o.portal && (
                      <Label isCompact color="blue" className="pf-v6-u-ml-sm">
                        portal
                      </Label>
                    )}
                    <div className="portal-muted portal-small">opid {String(o.opid)}</div>
                  </Td>
                  <Td dataLabel="Namespace" className="portal-mono">
                    {o.ns || '—'}
                  </Td>
                  <Td dataLabel="Running">{o.active ? fmtSecs(o.secsRunning) : '—'}</Td>
                  <Td dataLabel="Client" className="portal-mono">
                    {o.client || o.desc}
                    {o.appName && <div className="portal-muted portal-small">{o.appName}</div>}
                  </Td>
                  <Td dataLabel="User">{o.user || '—'}</Td>
                  <Td dataLabel="Plan" className="portal-mono">
                    {o.planSummary || '—'}
                  </Td>
                  <Td dataLabel="Actions" isActionCell>
                    {data.canKill && o.active && !o.internal && !o.killPending ? (
                      <Button variant="secondary" isDanger size="sm" onClick={() => setTarget(o)}>
                        End…
                      </Button>
                    ) : (
                      <Tooltip content={o.active ? 'Your portal role does not allow ending operations, or this is an internal operation' : 'Idle connections are not operations; killOp cannot close them'}>
                        <span className="portal-muted portal-small">—</span>
                      </Tooltip>
                    )}
                  </Td>
                </Tr>
              ))}
              {data.operations.length === 0 && (
                <Tr>
                  <Td colSpan={7}>Nothing matches the filters.</Td>
                </Tr>
              )}
            </Tbody>
          </Table>
          <Pagination
            itemCount={data.total}
            perPage={f.limit ?? 50}
            page={page}
            onSetPage={(_e, p) => setF((x) => ({ ...x, offset: (p - 1) * (x.limit ?? 50) }))}
            onPerPageSelect={(_e, n) => setF((x) => ({ ...x, limit: n, offset: 0 }))}
            perPageOptions={[25, 50, 100, 250].map((n) => ({ title: String(n), value: n }))}
            variant="bottom"
          />
        </>
      )}
      {target && <KillModal op={target} onClose={() => setTarget(undefined)} />}
    </PageSection>
  );
}
