import { useState } from 'react';
import {
  Alert,
  Button,
  Checkbox,
  Form,
  FormGroup,
  Label,
  LabelGroup,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalVariant,
  Spinner,
  Stack,
  TextInput,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { errorMessage } from '../../api/client';
import { useCreateIndex, useDropIndex, useIndexUsage, useIndexes } from '../../api/hooks';
import { ConfirmDialog } from '../../components/Dialogs';
import { JsonField, toExtJSON } from '../../components/JsonField';
import { canDo } from '../../components/Permission';
import { num } from '../../lib/ejson';
import { ErrorState } from '../StatusPages';

export function IndexesTab({ db, coll }: { db: string; coll: string }) {
  const idx = useIndexes(db, coll);
  const usage = useIndexUsage(db, coll);
  const drop = useDropIndex(db, coll);
  // $indexStats reports per member; sum the members the portal sees.
  const opsOf = (name: string) => {
    const rows = usage.data?.indexes.filter((u) => u.name === name) ?? [];
    return rows.length ? rows.reduce((a, u) => a + u.ops, 0) : undefined;
  };
  const sinceOf = (name: string) => usage.data?.indexes.find((u) => u.name === name)?.since;
  const [dropping, setDropping] = useState<string>();
  const [creating, setCreating] = useState(false);
  const access = idx.data?.access;

  return (
    <Stack hasGutter className="pf-v6-u-pt-md">
      {canDo(access, 'createIndex') && (
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <Button variant="secondary" onClick={() => setCreating(true)}>
                Create index
              </Button>
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
      )}
      {idx.isPending && <Spinner aria-label="Loading indexes" />}
      {idx.isError && <ErrorState error={idx.error} onRetry={() => void idx.refetch()} />}
      {idx.data && (
        <Table aria-label="Indexes" variant="compact">
          <Thead>
            <Tr>
              <Th>Name</Th>
              <Th>Keys</Th>
              <Th>Properties</Th>
              <Th info={{ tooltip: 'Operations served by the index since the member started or the index was built ($indexStats). Unused indexes cost writes and memory.' }}>Usage</Th>
              <Th screenReaderText="Actions" />
            </Tr>
          </Thead>
          <Tbody>
            {idx.data.indexes.map((ix) => {
              const name = String(ix.name);
              const ttl = num(ix.expireAfterSeconds);
              return (
                <Tr key={name}>
                  <Td dataLabel="Name" className="portal-mono">{name}</Td>
                  <Td dataLabel="Keys" className="portal-mono">{JSON.stringify(ix.key)}</Td>
                  <Td dataLabel="Properties">
                    <LabelGroup>
                      {ix.unique === true && <Label isCompact color="blue">unique</Label>}
                      {ix.sparse === true && <Label isCompact>sparse</Label>}
                      {ix.hidden === true && <Label isCompact>hidden</Label>}
                      {ttl !== undefined && <Label isCompact color="orange">TTL {ttl}s</Label>}
                      {'partialFilterExpression' in ix && (
                        <Label isCompact title={JSON.stringify(ix.partialFilterExpression)}>partial</Label>
                      )}
                    </LabelGroup>
                  </Td>
                  <Td dataLabel="Usage">
                    {opsOf(name) === undefined ? (
                      <span className="portal-muted">{usage.isError ? 'needs indexStats' : '—'}</span>
                    ) : (
                      <>
                        {opsOf(name)!.toLocaleString()} ops
                        {opsOf(name) === 0 && name !== '_id_' && (
                          <Label isCompact color="orange" className="pf-v6-u-ml-sm">
                            unused
                          </Label>
                        )}
                        {sinceOf(name) && <div className="portal-muted portal-small">since {new Date(sinceOf(name)!).toLocaleString()}</div>}
                      </>
                    )}
                  </Td>
                  <Td isActionCell>
                    {name !== '_id_' && canDo(access, 'dropIndex') && (
                      <Button variant="link" isDanger onClick={() => setDropping(name)}>
                        Drop
                      </Button>
                    )}
                  </Td>
                </Tr>
              );
            })}
          </Tbody>
        </Table>
      )}
      {dropping && (
        <ConfirmDialog
          title="Drop index"
          body={
            <>
              Dropping <strong>{dropping}</strong> may slow down queries that rely on it and can affect uniqueness guarantees.
            </>
          }
          typeToConfirm={dropping}
          confirmLabel="Drop index"
          onConfirm={() => drop.mutateAsync(dropping)}
          onClose={() => setDropping(undefined)}
        />
      )}
      {creating && <CreateIndexModal db={db} coll={coll} onClose={() => setCreating(false)} />}
    </Stack>
  );
}

function CreateIndexModal({ db, coll, onClose }: { db: string; coll: string; onClose: () => void }) {
  const [keys, setKeys] = useState('{"field": 1}');
  const [name, setName] = useState('');
  const [unique, setUnique] = useState(false);
  const [sparse, setSparse] = useState(false);
  const [hidden, setHidden] = useState(false);
  const [ttl, setTtl] = useState('');
  const [partial, setPartial] = useState('');
  const [error, setError] = useState<string>();
  const create = useCreateIndex(db, coll);

  const submit = async () => {
    setError(undefined);
    try {
      const options: Record<string, unknown> = {};
      if (name) options.name = name;
      if (unique) options.unique = true;
      if (sparse) options.sparse = true;
      if (hidden) options.hidden = true;
      if (ttl) {
        const n = Number(ttl);
        if (!Number.isInteger(n) || n < 0) throw new Error('TTL must be a non-negative integer');
        options.expireAfterSeconds = n;
      }
      if (partial.trim()) options.partialFilterExpression = JSON.parse(toExtJSON(partial));
      await create.mutateAsync({ keys: toExtJSON(keys), options: JSON.stringify(options) });
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  return (
    <Modal variant={ModalVariant.medium} isOpen onClose={onClose} aria-labelledby="create-index-title">
      <ModalHeader title="Create index" labelId="create-index-title" description={`${db}.${coll}. Index builds on large collections consume resources; follow your change process.`} />
      <ModalBody>
        <Form id="create-index-form" onSubmit={(e) => { e.preventDefault(); void submit(); }}>
          <JsonField id="ix-keys" label="Keys" value={keys} onChange={setKeys} required hint='1 / -1, or "text", "2dsphere", "hashed"' />
          <FormGroup label="Name (optional)" fieldId="ix-name">
            <TextInput id="ix-name" value={name} onChange={(_e, v) => setName(v)} />
          </FormGroup>
          <FormGroup role="group" label="Options" fieldId="ix-opts" isInline>
            <Checkbox id="ix-unique" label="Unique" isChecked={unique} onChange={(_e, v) => setUnique(v)} />
            <Checkbox id="ix-sparse" label="Sparse" isChecked={sparse} onChange={(_e, v) => setSparse(v)} />
            <Checkbox id="ix-hidden" label="Hidden" isChecked={hidden} onChange={(_e, v) => setHidden(v)} />
          </FormGroup>
          <FormGroup label="TTL in seconds (optional)" fieldId="ix-ttl">
            <TextInput id="ix-ttl" type="number" min={0} value={ttl} onChange={(_e, v) => setTtl(v)} />
          </FormGroup>
          <JsonField id="ix-partial" label="Partial filter expression (optional)" value={partial} onChange={setPartial} rows={2} />
        </Form>
        {error && <Alert variant="danger" isInline title={error} className="pf-v6-u-mt-md" />}
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="create-index-form" isLoading={create.isPending} isDisabled={create.isPending}>
          Create index
        </Button>
        <Button variant="link" onClick={onClose}>
          Cancel
        </Button>
      </ModalFooter>
    </Modal>
  );
}
