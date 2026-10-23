import { useState } from 'react';
import {
  ActionGroup,
  Alert,
  Button,
  Form,
  FormGroup,
  FormSelect,
  FormSelectOption,
  Grid,
  GridItem,
  NumberInput,
  Stack,
  Title,
} from '@patternfly/react-core';
import { errorMessage } from '../../api/client';
import { useRunQuery } from '../../api/hooks';
import type { QueryRequest } from '../../api/types';
import { JsonField, toExtJSON } from '../../components/JsonField';
import { DocumentCard } from './DocumentCard';

type Op = QueryRequest['operation'];

export function QueryTab({ db, coll }: { db: string; coll: string }) {
  const [op, setOp] = useState<Op>('find');
  const [filter, setFilter] = useState('');
  const [projection, setProjection] = useState('');
  const [sort, setSort] = useState('');
  const [pipeline, setPipeline] = useState('[\n  {"$match": {}},\n  {"$limit": 20}\n]');
  const [limit, setLimit] = useState(20);
  const [maxTimeMS, setMaxTimeMS] = useState(10000);
  const [inputError, setInputError] = useState<string>();
  const run = useRunQuery(db, coll);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setInputError(undefined);
    try {
      const q: QueryRequest = { operation: op, limit, maxTimeMS };
      if (op === 'aggregate') q.pipeline = toExtJSON(pipeline, 'array');
      else {
        q.filter = toExtJSON(filter);
        if (op !== 'countDocuments') {
          q.projection = toExtJSON(projection);
          q.sort = toExtJSON(sort);
        }
      }
      run.mutate(q);
    } catch (err) {
      setInputError(errorMessage(err));
    }
  };

  const res = run.data;
  return (
    <Stack hasGutter className="pf-v6-u-pt-md">
      <Alert variant="info" isInline isPlain title="Read-only query console">
        Supported operations: find, findOne, countDocuments and aggregate. Server-side JavaScript ($where, $function,
        $accumulator) and write stages ($out, $merge) are blocked. Results are limited by row count, execution time and size.
      </Alert>
      <Form onSubmit={submit} aria-label="Query console">
        <Grid hasGutter>
          <GridItem md={4}>
            <FormGroup label="Operation" fieldId="q-op">
              <FormSelect id="q-op" value={op} onChange={(_e, v) => setOp(v as Op)}>
                <FormSelectOption value="find" label="find" />
                <FormSelectOption value="findOne" label="findOne" />
                <FormSelectOption value="countDocuments" label="countDocuments" />
                <FormSelectOption value="aggregate" label="aggregate" />
              </FormSelect>
            </FormGroup>
          </GridItem>
          <GridItem md={4}>
            <FormGroup label="Limit" fieldId="q-limit">
              <NumberInput id="q-limit" value={limit} min={1} max={200}
                onMinus={() => setLimit(Math.max(1, limit - 10))} onPlus={() => setLimit(Math.min(200, limit + 10))}
                onChange={(e) => setLimit(Math.min(200, Math.max(1, Number((e.target as HTMLInputElement).value) || 1)))}
                inputAriaLabel="Result limit" minusBtnAriaLabel="Decrease limit" plusBtnAriaLabel="Increase limit" />
            </FormGroup>
          </GridItem>
          <GridItem md={4}>
            <FormGroup label="Max time (ms)" fieldId="q-maxtime">
              <NumberInput id="q-maxtime" value={maxTimeMS} min={100} max={60000}
                onMinus={() => setMaxTimeMS(Math.max(100, maxTimeMS - 1000))} onPlus={() => setMaxTimeMS(Math.min(60000, maxTimeMS + 1000))}
                onChange={(e) => setMaxTimeMS(Math.min(60000, Math.max(100, Number((e.target as HTMLInputElement).value) || 100)))}
                inputAriaLabel="Maximum execution time" minusBtnAriaLabel="Decrease time" plusBtnAriaLabel="Increase time" />
            </FormGroup>
          </GridItem>
        </Grid>
        {op === 'aggregate' ? (
          <JsonField id="q-pipeline" label="Pipeline" value={pipeline} onChange={setPipeline} want="array" rows={10} />
        ) : (
          <>
            <JsonField id="q-filter" label="Filter" value={filter} onChange={setFilter} placeholder="{}" rows={4} />
            {op !== 'countDocuments' && (
              <Grid hasGutter>
                <GridItem md={6}>
                  <JsonField id="q-projection" label="Projection" value={projection} onChange={setProjection} rows={2} />
                </GridItem>
                <GridItem md={6}>
                  <JsonField id="q-sort" label="Sort" value={sort} onChange={setSort} rows={2} />
                </GridItem>
              </Grid>
            )}
          </>
        )}
        {inputError && <Alert variant="danger" isInline title={inputError} />}
        <ActionGroup>
          <Button type="submit" isLoading={run.isPending} isDisabled={run.isPending}>
            Run
          </Button>
        </ActionGroup>
      </Form>

      {run.error && <Alert variant="danger" isInline title={errorMessage(run.error)} />}
      {res?.count !== undefined && (
        <Title headingLevel="h3">
          Count: {res.count}
          {res.countCapped ? '+' : ''}
        </Title>
      )}
      {res?.page && (
        <>
          <Title headingLevel="h3" size="md">
            {res.page.documents.length} result{res.page.documents.length === 1 ? '' : 's'}
            {res.page.hasMore ? ' (more available — increase the limit or refine the query)' : ''} · {res.page.elapsedMs} ms
          </Title>
          {res.page.truncated && <Alert variant="warning" isInline isPlain title="Results truncated by the response size limit." />}
          <Stack hasGutter>
            {res.page.documents.map((d, i) => (
              <DocumentCard key={i} doc={d} raw={false} />
            ))}
          </Stack>
        </>
      )}
    </Stack>
  );
}
