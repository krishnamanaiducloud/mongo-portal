import { useState } from 'react';
import { NavLink, useNavigate } from 'react-router';
import {
  Alert,
  Button,
  Form,
  FormGroup,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalVariant,
  PageSection,
  SearchInput,
  Spinner,
  TextInput,
  Title,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { useCreateCollection, useDatabases } from '../api/hooks';
import type { Me } from '../api/types';
import { errorMessage } from '../api/client';
import { formatBytes } from '../lib/ejson';
import { ErrorState } from './StatusPages';

export function DatabasesPage({ me }: { me: Me }) {
  const dbs = useDatabases();
  const [filter, setFilter] = useState('');
  const [creating, setCreating] = useState(false);
  const list = (dbs.data?.databases ?? []).filter((d) => d.name.toLowerCase().includes(filter.toLowerCase()));

  return (
    <PageSection>
      <Title headingLevel="h1" className="pf-v6-u-mb-md">
        Databases
      </Title>
      {dbs.data?.source === 'privileges' && (
        <Alert variant="info" isInline isPlain className="pf-v6-u-mb-md" title="Your MongoDB user cannot list databases. Showing databases referenced by your privileges." />
      )}
      <Toolbar>
        <ToolbarContent>
          <ToolbarItem>
            <SearchInput aria-label="Filter databases" placeholder="Filter databases" value={filter} onChange={(_e, v) => setFilter(v)} onClear={() => setFilter('')} />
          </ToolbarItem>
          {me.permissions['collections:create'] && (
            <ToolbarItem>
              <Button variant="secondary" onClick={() => setCreating(true)}>
                Create database
              </Button>
            </ToolbarItem>
          )}
        </ToolbarContent>
      </Toolbar>
      {dbs.data && dbs.data.source !== 'privileges' && dbs.data.totalSize !== undefined && (
        <div className="portal-db-summary" aria-label="Storage summary">
          <span>
            <span className="portal-muted">Total size on disk</span> <strong>{formatBytes(dbs.data.totalSize)}</strong>
          </span>
          <span>
            <span className="portal-muted">Databases</span> <strong>{dbs.data.databases.length}</strong>
          </span>
          {dbs.data.visibleSize !== undefined && dbs.data.visibleSize < dbs.data.totalSize && (
            <span>
              <span className="portal-muted">Shown to you</span> <strong>{formatBytes(dbs.data.visibleSize)}</strong>
            </span>
          )}
          <NavLink to="/monitoring" className="portal-small">
            Deployment monitoring
          </NavLink>
        </div>
      )}
      {dbs.isPending && <Spinner aria-label="Loading databases" />}
      {dbs.isError && <ErrorState error={dbs.error} onRetry={() => void dbs.refetch()} />}
      {dbs.data && (
        <Table aria-label="Databases" variant="compact">
          <Thead>
            <Tr>
              <Th>Name</Th>
              <Th>Size on disk</Th>
              <Th>Empty</Th>
            </Tr>
          </Thead>
          <Tbody>
            {list.map((d) => (
              <Tr key={d.name}>
                <Td dataLabel="Name">
                  <NavLink to={`/db/${encodeURIComponent(d.name)}`}>{d.name}</NavLink>
                </Td>
                <Td dataLabel="Size on disk">{dbs.data.source === 'privileges' ? '—' : formatBytes(d.sizeOnDisk)}</Td>
                <Td dataLabel="Empty">{d.empty ? 'yes' : 'no'}</Td>
              </Tr>
            ))}
            {list.length === 0 && (
              <Tr>
                <Td colSpan={3}>No databases visible to your MongoDB user.</Td>
              </Tr>
            )}
          </Tbody>
        </Table>
      )}
      {creating && <CreateDatabaseModal onClose={() => setCreating(false)} />}
    </PageSection>
  );
}

function CreateDatabaseModal({ onClose }: { onClose: () => void }) {
  const [db, setDb] = useState('');
  const [coll, setColl] = useState('');
  const create = useCreateCollection(db);
  const navigate = useNavigate();
  const submit = async () => {
    await create.mutateAsync({ database: db, name: coll });
    onClose();
    navigate(`/db/${encodeURIComponent(db)}/${encodeURIComponent(coll)}`);
  };
  return (
    <Modal variant={ModalVariant.small} isOpen onClose={onClose} aria-labelledby="create-db-title">
      <ModalHeader title="Create database" labelId="create-db-title" description="MongoDB creates a database when its first collection is created." />
      <ModalBody>
        <Form id="create-db-form" onSubmit={(e) => { e.preventDefault(); void submit().catch(() => undefined); }}>
          <FormGroup label="Database name" isRequired fieldId="new-db">
            <TextInput id="new-db" value={db} onChange={(_e, v) => setDb(v)} isRequired autoFocus />
          </FormGroup>
          <FormGroup label="First collection" isRequired fieldId="new-db-coll">
            <TextInput id="new-db-coll" value={coll} onChange={(_e, v) => setColl(v)} isRequired />
          </FormGroup>
        </Form>
        {create.error && <Alert variant="danger" isInline title={errorMessage(create.error)} className="pf-v6-u-mt-md" />}
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="create-db-form" isDisabled={!db || !coll} isLoading={create.isPending}>
          Create
        </Button>
        <Button variant="link" onClick={onClose}>
          Cancel
        </Button>
      </ModalFooter>
    </Modal>
  );
}
