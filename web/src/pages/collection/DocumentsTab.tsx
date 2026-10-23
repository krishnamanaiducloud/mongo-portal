import { useState } from 'react';
import {
  Alert,
  Button,
  ExpandableSection,
  Form,
  Grid,
  GridItem,
  Pagination,
  Spinner,
  Stack,
  Switch,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from '@patternfly/react-core';
import { PlusIcon } from '@patternfly/react-icons';
import { type FindParams, useDeleteDocument, useDocuments } from '../../api/hooks';
import { ConfirmDialog } from '../../components/Dialogs';
import { JsonField, toExtJSON } from '../../components/JsonField';
import { canDo } from '../../components/Permission';
import { ErrorState } from '../StatusPages';
import { DocumentCard } from './DocumentCard';
import { DocumentEditor } from './DocumentEditor';

export function DocumentsTab({ db, coll }: { db: string; coll: string }) {
  const [draft, setDraft] = useState({ filter: '', sort: '', projection: '' });
  const [params, setParams] = useState<FindParams>({ filter: '', sort: '', projection: '', skip: 0, limit: 20 });
  const [inputError, setInputError] = useState<string>();
  const [raw, setRaw] = useState(false);
  const [editing, setEditing] = useState<{ id?: string } | null>(null);
  const [deleting, setDeleting] = useState<string>();
  const docs = useDocuments(db, coll, params);
  const del = useDeleteDocument(db, coll);
  const access = docs.data?.access;

  const apply = (e?: React.FormEvent) => {
    e?.preventDefault();
    try {
      setParams({
        ...params,
        skip: 0,
        filter: toExtJSON(draft.filter),
        sort: toExtJSON(draft.sort),
        projection: toExtJSON(draft.projection),
      });
      setInputError(undefined);
    } catch (err) {
      setInputError(err instanceof Error ? err.message : 'Invalid input');
    }
  };

  const page = docs.data?.page;
  const known = docs.data?.count;
  const itemCount = known ?? (page ? params.skip + page.documents.length + (page.hasMore ? 1 : 0) : 0);

  return (
    <Stack hasGutter className="pf-v6-u-pt-md">
      <Form onSubmit={apply} aria-label="Document filter">
        <Grid hasGutter>
          <GridItem lg={8}>
            <JsonField id="filter" label="Filter" value={draft.filter} onChange={(v) => setDraft({ ...draft, filter: v })} placeholder='{"status": "active"}' rows={2} />
          </GridItem>
          <GridItem lg={4}>
            <JsonField id="sort" label="Sort" value={draft.sort} onChange={(v) => setDraft({ ...draft, sort: v })} placeholder='{"_id": -1}' rows={2} hint="1 ascending, -1 descending" />
          </GridItem>
        </Grid>
        <ExpandableSection toggleText="Projection">
          <JsonField id="projection" label="Projection" value={draft.projection} onChange={(v) => setDraft({ ...draft, projection: v })} placeholder='{"name": 1, "email": 1}' rows={2} />
        </ExpandableSection>
        {inputError && <Alert variant="danger" isInline title={inputError} />}
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <Button type="submit">Apply</Button>
            </ToolbarItem>
            <ToolbarItem>
              <Button
                variant="link"
                onClick={() => {
                  setDraft({ filter: '', sort: '', projection: '' });
                  setParams({ ...params, filter: '', sort: '', projection: '', skip: 0 });
                }}
              >
                Reset
              </Button>
            </ToolbarItem>
            <ToolbarItem>
              <Switch id="raw-toggle" label="Raw JSON" isChecked={raw} onChange={(_e, v) => setRaw(v)} />
            </ToolbarItem>
            {canDo(access, 'insert') && (
              <ToolbarItem>
                <Button variant="secondary" icon={<PlusIcon />} onClick={() => setEditing({})}>
                  Insert document
                </Button>
              </ToolbarItem>
            )}
            <ToolbarItem variant="pagination" align={{ default: 'alignEnd' }}>
              <Pagination
                itemCount={itemCount}
                perPage={params.limit}
                page={Math.floor(params.skip / params.limit) + 1}
                perPageOptions={[10, 20, 50, 100, 200].map((n) => ({ title: String(n), value: n }))}
                onSetPage={(_e, p) => setParams({ ...params, skip: (p - 1) * params.limit })}
                onPerPageSelect={(_e, n) => setParams({ ...params, limit: n, skip: 0 })}
                toggleTemplate={({ firstIndex, lastIndex }) => (
                  <>
                    <b>
                      {firstIndex}–{lastIndex}
                    </b>{' '}
                    of <b>{known === undefined ? 'many' : `${known}${docs.data?.countCapped ? '+' : ''}`}</b>
                  </>
                )}
                isCompact
              />
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
      </Form>

      {docs.isPending && <Spinner aria-label="Loading documents" />}
      {docs.isError && <ErrorState error={docs.error} onRetry={() => void docs.refetch()} />}
      {page?.truncated && (
        <Alert variant="warning" isInline isPlain title="Results were truncated to stay within the response size limit. Use a projection or a smaller page size." />
      )}
      {page && (
        <div aria-busy={docs.isFetching}>
          {page.documents.length === 0 && <p>No documents match.</p>}
          <Stack hasGutter>
            {page.documents.map((d, i) => (
              <DocumentCard
                key={page.ids[i] || i}
                doc={d}
                id={page.ids[i]}
                access={access}
                raw={raw}
                onEdit={(id) => setEditing({ id })}
                onDelete={(id) => setDeleting(id)}
              />
            ))}
          </Stack>
          <p className="pf-v6-u-font-size-sm pf-v6-u-color-200 pf-v6-u-mt-sm">Query time {page.elapsedMs} ms</p>
        </div>
      )}

      {editing && <DocumentEditor db={db} coll={coll} id={editing.id} onClose={() => setEditing(null)} />}
      {deleting && (
        <ConfirmDialog
          title="Delete document"
          body="This permanently deletes the selected document. This cannot be undone."
          confirmLabel="Delete"
          onConfirm={() => del.mutateAsync(deleting)}
          onClose={() => setDeleting(undefined)}
        />
      )}
    </Stack>
  );
}
