import { useState } from 'react';
import { NavLink, useParams } from 'react-router';
import {
  Alert,
  Breadcrumb,
  BreadcrumbItem,
  Button,
  Card,
  CardBody,
  CardTitle,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Flex,
  Form,
  FormGroup,
  Label,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  ModalVariant,
  PageSection,
  Spinner,
  TextInput,
  Title,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { useCollections, useCreateCollection, useDatabaseStats, useDropCollection } from '../api/hooks';
import { errorMessage } from '../api/client';
import { formatBytes, num } from '../lib/ejson';
import { AccessLabel, canDo } from '../components/Permission';
import { ConfirmDialog } from '../components/Dialogs';
import { ErrorState } from './StatusPages';

export function DatabasePage() {
  const { db = '' } = useParams();
  const colls = useCollections(db);
  const stats = useDatabaseStats(db);
  const drop = useDropCollection(db);
  const [dropping, setDropping] = useState<string>();
  const [creating, setCreating] = useState(false);
  const access = colls.data?.access;

  return (
    <PageSection>
      <Breadcrumb className="pf-v6-u-mb-md">
        <BreadcrumbItem render={() => <NavLink to="/databases">Databases</NavLink>} />
        <BreadcrumbItem isActive>{db}</BreadcrumbItem>
      </Breadcrumb>
      <Flex alignItems={{ default: 'alignItemsCenter' }} className="pf-v6-u-mb-md">
        <Title headingLevel="h1">{db}</Title>
        <AccessLabel access={access} />
      </Flex>

      <Card className="pf-v6-u-mb-lg" isCompact>
        <CardTitle>Database statistics</CardTitle>
        <CardBody>
          {stats.isPending && <Spinner size="md" aria-label="Loading statistics" />}
          {stats.isError && <Alert variant="info" isInline isPlain title={`Statistics unavailable: ${errorMessage(stats.error)}`} />}
          {stats.data && (
            <DescriptionList isHorizontal isCompact columnModifier={{ default: '2Col', lg: '3Col' }}>
              {(
                [
                  ['Collections', num(stats.data.stats.collections)],
                  ['Views', num(stats.data.stats.views)],
                  ['Documents', num(stats.data.stats.objects)],
                  ['Data size', formatBytes(num(stats.data.stats.dataSize))],
                  ['Storage size', formatBytes(num(stats.data.stats.storageSize))],
                  ['Indexes', num(stats.data.stats.indexes)],
                  ['Index size', formatBytes(num(stats.data.stats.indexSize))],
                ] as [string, unknown][]
              ).map(([k, v]) => (
                <DescriptionListGroup key={k}>
                  <DescriptionListTerm>{k}</DescriptionListTerm>
                  <DescriptionListDescription>{v === undefined ? '—' : String(v)}</DescriptionListDescription>
                </DescriptionListGroup>
              ))}
            </DescriptionList>
          )}
        </CardBody>
      </Card>

      <Flex justifyContent={{ default: 'justifyContentSpaceBetween' }} className="pf-v6-u-mb-sm">
        <Title headingLevel="h2" size="lg">
          Collections
        </Title>
        {canDo(access, 'createCollection') && (
          <Button variant="secondary" onClick={() => setCreating(true)}>
            Create collection
          </Button>
        )}
      </Flex>
      {colls.isPending && <Spinner aria-label="Loading collections" />}
      {colls.isError && <ErrorState error={colls.error} onRetry={() => void colls.refetch()} />}
      {colls.data && (
        <Table aria-label="Collections" variant="compact">
          <Thead>
            <Tr>
              <Th>Name</Th>
              <Th>Type</Th>
              <Th>Access</Th>
              <Th screenReaderText="Actions" />
            </Tr>
          </Thead>
          <Tbody>
            {colls.data.collections.map((c) => (
              <Tr key={c.name}>
                <Td dataLabel="Name">
                  <NavLink to={`/db/${encodeURIComponent(db)}/${encodeURIComponent(c.name)}`}>{c.name}</NavLink>
                </Td>
                <Td dataLabel="Type">
                  {c.type || 'collection'} {c.readOnly && <Label isCompact>read-only</Label>}
                </Td>
                <Td dataLabel="Access">
                  <AccessLabel access={c.access} />
                </Td>
                <Td isActionCell>
                  {canDo(c.access, 'dropCollection') && !c.name.startsWith('system.') && (
                    <Button variant="link" isDanger onClick={() => setDropping(c.name)}>
                      Drop
                    </Button>
                  )}
                </Td>
              </Tr>
            ))}
            {colls.data.collections.length === 0 && (
              <Tr>
                <Td colSpan={4}>No collections visible to your MongoDB user.</Td>
              </Tr>
            )}
          </Tbody>
        </Table>
      )}

      {dropping && (
        <ConfirmDialog
          title="Drop collection"
          body={
            <>
              This permanently deletes the collection <strong>{db}.{dropping}</strong>, all its documents and indexes. This cannot be undone.
            </>
          }
          typeToConfirm={dropping}
          confirmLabel="Drop collection"
          onConfirm={() => drop.mutateAsync(dropping)}
          onClose={() => setDropping(undefined)}
        />
      )}
      {creating && <CreateCollectionModal db={db} onClose={() => setCreating(false)} />}
    </PageSection>
  );
}

function CreateCollectionModal({ db, onClose }: { db: string; onClose: () => void }) {
  const [name, setName] = useState('');
  const create = useCreateCollection(db);
  return (
    <Modal variant={ModalVariant.small} isOpen onClose={onClose} aria-labelledby="create-coll-title">
      <ModalHeader title={`Create collection in ${db}`} labelId="create-coll-title" />
      <ModalBody>
        <Form id="create-coll-form" onSubmit={(e) => { e.preventDefault(); void create.mutateAsync({ name }).then(onClose, () => undefined); }}>
          <FormGroup label="Collection name" isRequired fieldId="new-coll">
            <TextInput id="new-coll" value={name} onChange={(_e, v) => setName(v)} isRequired autoFocus />
          </FormGroup>
        </Form>
        {create.error && <Alert variant="danger" isInline title={errorMessage(create.error)} className="pf-v6-u-mt-md" />}
      </ModalBody>
      <ModalFooter>
        <Button type="submit" form="create-coll-form" isDisabled={!name} isLoading={create.isPending}>
          Create
        </Button>
        <Button variant="link" onClick={onClose}>
          Cancel
        </Button>
      </ModalFooter>
    </Modal>
  );
}
