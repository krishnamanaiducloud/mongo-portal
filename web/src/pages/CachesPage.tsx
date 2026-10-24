import { useState } from 'react';
import {
  Alert,
  AlertActionCloseButton,
  Button,
  Card,
  CardBody,
  CardTitle,
  Content,
  Form,
  FormGroup,
  Label,
  LabelGroup,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalVariant,
  PageSection,
  TextInput,
  ToggleGroup,
  ToggleGroupItem,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { CheckCircleIcon, ExclamationCircleIcon, LayerGroupIcon, SyncAltIcon } from '@patternfly/react-icons';
import { errorMessage } from '../api/client';
import { useCaches, useInvalidateCaches } from '../api/hooks';
import type { InvalidateResult } from '../api/types';
import { PageHeader } from '../components/PageHeader';
import { ErrorState } from './StatusPages';

function when(iso?: string) {
  return iso ? new Date(iso).toLocaleString() : '—';
}

export function CachesPage() {
  const q = useCaches();
  const inv = useInvalidateCaches();
  const [selected, setSelected] = useState<string[]>([]);
  const [scope, setScope] = useState<'all' | 'replica'>('all');
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirm, setConfirm] = useState('');
  const [result, setResult] = useState<InvalidateResult>();
  const d = q.data;

  const toggle = (name: string, on: boolean) => setSelected((s) => (on ? [...s, name] : s.filter((x) => x !== name)));
  const run = async () => {
    try {
      setResult(await inv.mutateAsync({ caches: selected, scope, confirm }));
      setSelected([]);
    } finally {
      setConfirmOpen(false);
      setConfirm('');
    }
  };

  return (
    <PageSection>
      <PageHeader
        icon={<LayerGroupIcon />}
        title="Caches"
        description="The portal's own caches on each replica. Invalidating re-reads or re-checks their source; it never deletes data and never touches MongoDB's cache or storage."
        actions={<Button variant="plain" aria-label="Refresh" icon={<SyncAltIcon />} onClick={() => void q.refetch()} />}
      />
      {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}
      {result && (
        <Alert
          className="pf-v6-u-mb-md"
          isInline
          variant={result.results.every((r) => r.ok) ? 'success' : 'warning'}
          title={result.results.every((r) => r.ok) ? 'Caches invalidated' : 'Some caches could not be refreshed'}
          actionClose={<AlertActionCloseButton onClose={() => setResult(undefined)} />}
        >
          {result.results.map((r) => (
            <div key={r.name}>
              {r.ok ? <CheckCircleIcon className="portal-status-success" /> : <ExclamationCircleIcon className="portal-status-danger" />} {r.name}
              {r.error ? `: ${r.error}` : ''}
            </div>
          ))}
          {result.note && <p className="pf-v6-u-mt-sm">{result.note}</p>}
        </Alert>
      )}
      {inv.isError && <Alert className="pf-v6-u-mb-md" isInline variant="danger" title={errorMessage(inv.error)} />}
      {d && (
        <>
          <Card className="pf-v6-u-mb-lg">
            <CardTitle>
              Replica <span className="portal-mono">{d.pod || 'this replica'}</span>
              <span className="portal-card-sub">
                {' '}
                · {d.shared ? 'invalidations reach every replica through the shared store' : 'no shared store: invalidations apply to this replica only'}
              </span>
            </CardTitle>
            <CardBody>
              <Table aria-label="Portal caches" variant="compact">
                <Thead>
                  <Tr>
                    <Th screenReaderText="Select" />
                    <Th width={60}>Cache</Th>
                    <Th modifier="nowrap">Entries</Th>
                    <Th modifier="nowrap">Last refreshed</Th>
                    <Th modifier="nowrap">State</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {d.caches.map((c, i) => (
                    <Tr key={c.name}>
                      <Td
                        select={{
                          rowIndex: i,
                          onSelect: (_e, on) => toggle(c.name, on),
                          isSelected: selected.includes(c.name),
                          isDisabled: !d.canInvalidate,
                        }}
                      />
                      <Td dataLabel="Cache">
                        <strong>{c.title}</strong>
                        <div className="portal-muted portal-small">{c.description}</div>
                      </Td>
                      <Td dataLabel="Entries">{c.entries}</Td>
                      <Td dataLabel="Last refreshed">{when(c.refreshedAt)}</Td>
                      <Td dataLabel="State">
                        {c.lastError ? (
                          <Label color="orange" isCompact title={c.lastError}>
                            {c.lastError.length > 60 ? `${c.lastError.slice(0, 60)}…` : c.lastError}
                          </Label>
                        ) : (
                          <Label color="green" isCompact>
                            ok
                          </Label>
                        )}
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
              {d.canInvalidate ? (
                <div className="portal-toolbar-row pf-v6-u-mt-md">
                  <ToggleGroup aria-label="Scope">
                    <ToggleGroupItem text="All replicas" isSelected={scope === 'all'} onChange={() => setScope('all')} isDisabled={!d.shared} />
                    <ToggleGroupItem text="This replica" isSelected={scope === 'replica' || !d.shared} onChange={() => setScope('replica')} />
                  </ToggleGroup>
                  <Button variant="primary" isDisabled={selected.length === 0} onClick={() => setConfirmOpen(true)} isLoading={inv.isPending}>
                    Invalidate {selected.length || ''} selected
                  </Button>
                </div>
              ) : (
                <Content component="small" className="portal-muted">
                  Your role can view caches. Invalidating needs the cache delete permission.
                </Content>
              )}
            </CardBody>
          </Card>
          {d.shared && (
            <Card>
              <CardTitle>Recent invalidations</CardTitle>
              <CardBody>
                {d.recentError && <Alert isInline isPlain variant="warning" title={d.recentError} />}
                {(d.recent ?? []).length === 0 && !d.recentError && <Content component="p" className="portal-muted">None in the last 7 days.</Content>}
                {(d.recent ?? []).length > 0 && (
                  <Table aria-label="Recent invalidations" variant="compact">
                    <Thead>
                      <Tr>
                        <Th>When</Th>
                        <Th>By</Th>
                        <Th>Caches</Th>
                        <Th>Applied on</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {d.recent!.map((r) => (
                        <Tr key={r.id}>
                          <Td dataLabel="When">{when(r.at)}</Td>
                          <Td dataLabel="By">{r.requestedBy || '—'}</Td>
                          <Td dataLabel="Caches">{r.caches.join(', ')}</Td>
                          <Td dataLabel="Applied on">
                            <LabelGroup numLabels={6}>
                              {r.applied.map((a) => (
                                <Label key={a.pod} isCompact color={a.errors?.length ? 'orange' : 'green'} title={a.errors?.join('; ') || when(a.at)}>
                                  {a.pod}
                                </Label>
                              ))}
                            </LabelGroup>
                          </Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                )}
              </CardBody>
            </Card>
          )}
        </>
      )}
      <Modal variant={ModalVariant.small} isOpen={confirmOpen} onClose={() => setConfirmOpen(false)} aria-labelledby="inv-title">
        <ModalHeader title="Invalidate caches" labelId="inv-title" titleIconVariant="warning" />
        <ModalBody>
          <Content component="p">
            {selected.join(', ')} will be refreshed {scope === 'all' && d?.shared ? 'on every replica' : 'on this replica'}. Signed-in users may see a short
            delay while sources are checked again. No data is deleted.
          </Content>
          <Form onSubmit={(e) => { e.preventDefault(); if (confirm === 'invalidate') void run(); }}>
            <FormGroup label='Type "invalidate" to confirm' fieldId="inv-confirm">
              <TextInput id="inv-confirm" value={confirm} onChange={(_e, v) => setConfirm(v)} autoFocus />
            </FormGroup>
          </Form>
        </ModalBody>
        <ModalFooter>
          <Button variant="danger" isDisabled={confirm !== 'invalidate'} onClick={() => void run()} isLoading={inv.isPending}>
            Invalidate
          </Button>
          <Button variant="link" onClick={() => setConfirmOpen(false)}>
            Cancel
          </Button>
        </ModalFooter>
      </Modal>
    </PageSection>
  );
}
