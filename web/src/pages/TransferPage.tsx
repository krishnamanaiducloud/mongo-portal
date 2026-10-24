import { useMemo, useState } from 'react';
import { useSearchParams } from 'react-router';
import {
  ActionGroup,
  Alert,
  Button,
  Card,
  CardBody,
  CardTitle,
  Checkbox,
  ClipboardCopy,
  Content,
  ExpandableSection,
  FileUpload,
  Flex,
  FlexItem,
  Form,
  FormGroup,
  FormHelperText,
  FormSelect,
  FormSelectOption,
  Grid,
  GridItem,
  HelperText,
  HelperTextItem,
  Label,
  PageSection,
  Progress,
  ProgressSize,
  Radio,
  Tab,
  Tabs,
  TabTitleText,
  TextArea,
  TextInput,
  Title,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { BanIcon, CheckCircleIcon, DownloadIcon, ExclamationCircleIcon, InProgressIcon, UploadIcon } from '@patternfly/react-icons';
import { errorMessage, nsPath, qs, upload } from '../api/client';
import { useQueryClient } from '@tanstack/react-query';
import { keys, useCancelJob, useCollections, useDatabases, useJobs } from '../api/hooks';
import type { FieldMap, ImportPreview, Job, Me, TransferFormat } from '../api/types';
import { DocumentView } from '../components/DocumentView';
import { formatBytes } from '../lib/ejson';

const formats: { value: TransferFormat; label: string; help: string }[] = [
  { value: 'ndjson', label: 'Extended JSON, one document per line (.json)', help: 'mongoimport/mongoexport default; best for large data' },
  { value: 'json', label: 'JSON array', help: 'One array; easy to read in other tools' },
  { value: 'csv', label: 'CSV', help: 'Columns from field paths; nested values as Extended JSON' },
  { value: 'tsv', label: 'TSV', help: 'Tab-separated columns' },
  { value: 'bson', label: 'BSON (.bson)', help: 'Exact binary documents, as in mongodump' },
];

const fieldTypes = ['auto', 'string', 'int', 'long', 'double', 'decimal', 'bool', 'date', 'objectId'];

function guessFormat(name: string): TransferFormat {
  const n = name.toLowerCase().replace(/\.gz$/, '');
  if (n.endsWith('.csv')) return 'csv';
  if (n.endsWith('.tsv')) return 'tsv';
  if (n.endsWith('.bson')) return 'bson';
  if (n.endsWith('.ndjson') || n.endsWith('.jsonl')) return 'ndjson';
  return 'ndjson';
}

function NamespacePicker({ db, coll, onDb, onColl }: { db: string; coll: string; onDb: (v: string) => void; onColl: (v: string) => void }) {
  const dbs = useDatabases();
  const colls = useCollections(db || undefined);
  return (
    <Grid hasGutter>
      <GridItem md={6}>
        <FormGroup label="Database" fieldId="tr-db" isRequired>
          <FormSelect id="tr-db" value={db} onChange={(_e, v) => onDb(v)}>
            <FormSelectOption value="" label="Choose a database" isPlaceholder />
            {(dbs.data?.databases ?? []).map((d) => (
              <FormSelectOption key={d.name} value={d.name} label={d.name} />
            ))}
          </FormSelect>
        </FormGroup>
      </GridItem>
      <GridItem md={6}>
        <FormGroup label="Collection" fieldId="tr-coll" isRequired>
          <TextInput id="tr-coll" value={coll} onChange={(_e, v) => onColl(v)} list="tr-coll-list" placeholder="existing or new collection" />
          <datalist id="tr-coll-list">
            {(colls.data?.collections ?? []).map((c) => (
              <option key={c.name} value={c.name} />
            ))}
          </datalist>
        </FormGroup>
      </GridItem>
    </Grid>
  );
}

function ExportPanel({ me, db, coll }: { me: Me; db: string; coll: string }) {
  const [format, setFormat] = useState<TransferFormat>('ndjson');
  const [canonical, setCanonical] = useState(false);
  const [gzip, setGzip] = useState(false);
  const [filter, setFilter] = useState('');
  const [projection, setProjection] = useState('');
  const [sort, setSort] = useState('');
  const [limit, setLimit] = useState('');
  const [fields, setFields] = useState('');
  const [dbFormat, setDbFormat] = useState<'ndjson' | 'json' | 'bson'>('ndjson');
  const allowed = me.permissions['export:create'] !== false;
  const isText = format === 'json' || format === 'ndjson';
  const href =
    db && coll
      ? `/api/v1${nsPath(db, coll)}/export${qs({
          format,
          ejson: isText && canonical ? 'canonical' : undefined,
          gzip,
          filter: filter.trim() || undefined,
          projection: projection.trim() || undefined,
          sort: sort.trim() || undefined,
          limit: limit || undefined,
          fields: (format === 'csv' || format === 'tsv') && fields.trim() ? fields.trim() : undefined,
        })}`
      : '';
  const dbHref = db ? `/api/v1${nsPath(db)}/export${qs({ format: dbFormat, ejson: canonical && dbFormat !== 'bson' ? 'canonical' : undefined })}` : '';
  return (
    <Grid hasGutter>
      <GridItem lg={7}>
        <Card>
          <CardTitle>Export a collection</CardTitle>
          <CardBody>
            {!allowed && <Alert variant="info" isInline isPlain className="pf-v6-u-mb-md" title="Your portal role does not include export." />}
            <Form onSubmit={(e) => e.preventDefault()}>
              <FormGroup label="Format" role="radiogroup" fieldId="ex-format" isStack>
                {formats.map((f) => (
                  <Radio key={f.value} id={`ex-${f.value}`} name="ex-format" label={f.label} description={f.help} isChecked={format === f.value} onChange={() => setFormat(f.value)} />
                ))}
              </FormGroup>
              {isText && (
                <Checkbox id="ex-canonical" label="Canonical Extended JSON (exact types, for round trips)" isChecked={canonical} onChange={(_e, v) => setCanonical(v)} />
              )}
              <Checkbox id="ex-gzip" label="Compress with gzip" isChecked={gzip} onChange={(_e, v) => setGzip(v)} />
              <ExpandableSection toggleText="Filter, projection, sort and limit">
                <FormGroup label="Filter" fieldId="ex-filter">
                  <TextArea id="ex-filter" className="portal-mono" value={filter} onChange={(_e, v) => setFilter(v)} placeholder='{ "status": "A" }' autoResize />
                </FormGroup>
                <FormGroup label="Projection" fieldId="ex-proj">
                  <TextArea id="ex-proj" className="portal-mono" value={projection} onChange={(_e, v) => setProjection(v)} placeholder='{ "name": 1, "total": 1 }' autoResize />
                </FormGroup>
                <FormGroup label="Sort" fieldId="ex-sort">
                  <TextInput id="ex-sort" className="portal-mono" value={sort} onChange={(_e, v) => setSort(v)} placeholder='{ "_id": 1 }' />
                </FormGroup>
                <FormGroup label="Limit" fieldId="ex-limit">
                  <TextInput id="ex-limit" type="number" min={1} value={limit} onChange={(_e, v) => setLimit(v)} />
                </FormGroup>
                {(format === 'csv' || format === 'tsv') && (
                  <FormGroup label="Columns" fieldId="ex-fields">
                    <TextInput id="ex-fields" value={fields} onChange={(_e, v) => setFields(v)} placeholder="_id,name,address.city" />
                    <FormHelperText>
                      <HelperText>
                        <HelperTextItem>Without columns, the fields of the first document are used.</HelperTextItem>
                      </HelperText>
                    </FormHelperText>
                  </FormGroup>
                )}
              </ExpandableSection>
              <ActionGroup>
                <Button component="a" href={href || undefined} download icon={<DownloadIcon />} isDisabled={!href || !allowed} variant="primary">
                  Download {coll ? `${db}.${coll}` : ''}
                </Button>
              </ActionGroup>
              <Content component="small">
                The download streams directly from MongoDB with your session; cancelling the download stops the export. Every export is
                audited.
              </Content>
            </Form>
          </CardBody>
        </Card>
      </GridItem>
      <GridItem lg={5}>
        <Card>
          <CardTitle>Export a whole database</CardTitle>
          <CardBody>
            <Content component="p">
              A zip archive with one file per collection you may export, each collection's options and indexes, and a manifest with document
              counts and SHA-256 checksums.
            </Content>
            <FormGroup label="Format" fieldId="dbx-format">
              <FormSelect id="dbx-format" value={dbFormat} onChange={(_e, v) => setDbFormat(v as 'ndjson' | 'json' | 'bson')}>
                <FormSelectOption value="ndjson" label="Extended JSON lines" />
                <FormSelectOption value="json" label="JSON arrays" />
                <FormSelectOption value="bson" label="BSON" />
              </FormSelect>
            </FormGroup>
            <Button className="pf-v6-u-mt-md" component="a" href={dbHref || undefined} download icon={<DownloadIcon />} variant="secondary" isDisabled={!dbHref || !allowed}>
              Download {db || 'database'}.zip
            </Button>
            <Alert className="pf-v6-u-mt-md" variant="warning" isInline isPlain title="Not a backup">
              Collections are read one after another without a snapshot. Use your MongoDB backup tooling for consistent, point-in-time
              backups.
            </Alert>
          </CardBody>
        </Card>
      </GridItem>
    </Grid>
  );
}

function MappingEditor({ preview, mapping, onChange }: { preview: ImportPreview; mapping: FieldMap[]; onChange: (m: FieldMap[]) => void }) {
  const cols = preview.columns ?? [];
  const get = (c: string) => mapping.find((m) => m.column === c) ?? { column: c };
  const set = (c: string, patch: Partial<FieldMap>) => {
    const next = cols.map((col) => (col === c ? { ...get(col), ...patch } : get(col)));
    onChange(next);
  };
  return (
    <Table aria-label="Column mapping" variant="compact">
      <Thead>
        <Tr>
          <Th>Column</Th>
          <Th>Field</Th>
          <Th>Type</Th>
          <Th>Detected</Th>
          <Th>Skip</Th>
        </Tr>
      </Thead>
      <Tbody>
        {cols.map((c) => {
          const m = get(c);
          return (
            <Tr key={c}>
              <Td dataLabel="Column" className="portal-mono">
                {c}
              </Td>
              <Td dataLabel="Field">
                <TextInput aria-label={`Field for ${c}`} value={m.field ?? ''} placeholder={c} onChange={(_e, v) => set(c, { field: v || undefined })} isDisabled={m.skip} />
              </Td>
              <Td dataLabel="Type">
                <FormSelect aria-label={`Type for ${c}`} value={m.type ?? 'auto'} onChange={(_e, v) => set(c, { type: v === 'auto' ? undefined : v })} isDisabled={m.skip}>
                  {fieldTypes.map((t) => (
                    <FormSelectOption key={t} value={t} label={t} />
                  ))}
                </FormSelect>
              </Td>
              <Td dataLabel="Detected">{preview.types?.[m.field || c] ?? '—'}</Td>
              <Td dataLabel="Skip">
                <Checkbox id={`skip-${c}`} aria-label={`Skip ${c}`} isChecked={!!m.skip} onChange={(_e, v) => set(c, { skip: v })} />
              </Td>
            </Tr>
          );
        })}
      </Tbody>
    </Table>
  );
}

function ImportPanel({ me, db, coll, onStarted }: { me: Me; db: string; coll: string; onStarted: () => void }) {
  const qc = useQueryClient();
  const [file, setFile] = useState<File | undefined>();
  const [format, setFormat] = useState<TransferFormat>('ndjson');
  const [mode, setMode] = useState<'insert' | 'upsert'>('insert');
  const [dryRun, setDryRun] = useState(false);
  const [keepBlanks, setKeepBlanks] = useState(false);
  const [mapping, setMapping] = useState<FieldMap[]>([]);
  const [preview, setPreview] = useState<ImportPreview>();
  const [busy, setBusy] = useState<'preview' | 'upload' | undefined>();
  const [error, setError] = useState<string>();
  const allowed = me.permissions['import:create'] !== false && me.permissions['documents:create'] !== false;
  const tabular = format === 'csv' || format === 'tsv';
  const params = () =>
    qs({
      format,
      mode,
      dryRun,
      keepBlanks: tabular && keepBlanks,
      mapping: tabular && mapping.some((m) => m.field || m.type || m.skip) ? JSON.stringify(mapping) : undefined,
      fileName: file?.name,
    });

  const doPreview = async () => {
    if (!file || !db || !coll) return;
    setBusy('preview');
    setError(undefined);
    try {
      setPreview(await upload<ImportPreview>(`${nsPath(db, coll)}/import/preview${params()}`, file.slice(0, 1 << 20)));
    } catch (e) {
      setPreview(undefined);
      setError(errorMessage(e));
    } finally {
      setBusy(undefined);
    }
  };
  const doImport = async () => {
    if (!file || !db || !coll) return;
    setBusy('upload');
    setError(undefined);
    try {
      await upload<Job>(`${nsPath(db, coll)}/import${params()}`, file);
      await qc.invalidateQueries({ queryKey: keys.jobs });
      onStarted();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(undefined);
    }
  };

  return (
    <Grid hasGutter>
      <GridItem lg={6}>
        <Card>
          <CardTitle>Import into {db && coll ? `${db}.${coll}` : 'a collection'}</CardTitle>
          <CardBody>
            {!allowed && <Alert variant="info" isInline isPlain className="pf-v6-u-mb-md" title="Your portal role does not include import." />}
            <Form onSubmit={(e) => e.preventDefault()}>
              <FormGroup label="File" fieldId="im-file" isRequired>
                <FileUpload
                  id="im-file"
                  filename={file?.name ?? ''}
                  filenamePlaceholder="Drag a file here or browse"
                  browseButtonText="Browse"
                  hideDefaultPreview
                  onFileInputChange={(_e, f) => {
                    setFile(f);
                    setFormat(guessFormat(f.name));
                    setPreview(undefined);
                    setMapping([]);
                  }}
                  onClearClick={() => {
                    setFile(undefined);
                    setPreview(undefined);
                  }}
                />
                {file && (
                  <FormHelperText>
                    <HelperText>
                      <HelperTextItem>
                        {formatBytes(file.size)}
                        {file.name.toLowerCase().endsWith('.gz') ? ' · gzip is decompressed automatically' : ''}
                      </HelperTextItem>
                    </HelperText>
                  </FormHelperText>
                )}
              </FormGroup>
              <FormGroup label="Format" fieldId="im-format">
                <FormSelect id="im-format" value={format} onChange={(_e, v) => { setFormat(v as TransferFormat); setPreview(undefined); }}>
                  {formats.map((f) => (
                    <FormSelectOption key={f.value} value={f.value} label={f.label} />
                  ))}
                </FormSelect>
              </FormGroup>
              <FormGroup label="Mode" role="radiogroup" fieldId="im-mode" isInline>
                <Radio id="im-insert" name="im-mode" label="Insert" description="Existing _id values are reported as duplicates" isChecked={mode === 'insert'} onChange={() => setMode('insert')} />
                <Radio id="im-upsert" name="im-mode" label="Upsert by _id" description="Replaces existing documents" isChecked={mode === 'upsert'} onChange={() => setMode('upsert')} />
              </FormGroup>
              <Checkbox id="im-dry" label="Dry run: parse and validate the file, write nothing" isChecked={dryRun} onChange={(_e, v) => setDryRun(v)} />
              {tabular && <Checkbox id="im-blanks" label="Keep empty cells as empty strings" isChecked={keepBlanks} onChange={(_e, v) => setKeepBlanks(v)} />}
              {error && <Alert variant="danger" isInline title={error} />}
              <ActionGroup>
                <Button variant="secondary" onClick={() => void doPreview()} isDisabled={!file || !db || !coll || !!busy} isLoading={busy === 'preview'}>
                  Preview
                </Button>
                <Button variant="primary" icon={<UploadIcon />} onClick={() => void doImport()} isDisabled={!file || !db || !coll || !!busy || !allowed} isLoading={busy === 'upload'}>
                  {dryRun ? 'Validate file' : 'Import'}
                </Button>
              </ActionGroup>
              <Content component="small">
                Documents are written with your MongoDB session in batches; collection validators apply and rejected documents are listed per
                record. The import runs in the background on this portal replica.
              </Content>
            </Form>
          </CardBody>
        </Card>
      </GridItem>
      <GridItem lg={6}>
        <Card>
          <CardTitle>Preview</CardTitle>
          <CardBody>
            {!preview && <Content component="p">Preview shows how the first part of the file will be read, without writing anything.</Content>}
            {preview && (
              <>
                <Flex className="pf-v6-u-mb-sm" gap={{ default: 'gapSm' }}>
                  <Label isCompact>{preview.format}</Label>
                  {preview.gzip && <Label isCompact>gzip</Label>}
                  <Label isCompact color="blue">
                    {preview.documents.length} documents
                  </Label>
                  {preview.errors.length > 0 && (
                    <Label isCompact color="red">
                      {preview.errors.length} unreadable records
                    </Label>
                  )}
                  {preview.partial && <Label isCompact>sample ends mid-record</Label>}
                </Flex>
                {preview.columns && (
                  <>
                    <Title headingLevel="h4" size="md">
                      Column mapping
                    </Title>
                    <MappingEditor preview={preview} mapping={mapping} onChange={setMapping} />
                    <Button variant="link" isInline onClick={() => void doPreview()}>
                      Apply mapping to the preview
                    </Button>
                  </>
                )}
                {preview.errors.map((e) => (
                  <Alert key={e.record} variant="warning" isInline isPlain title={`Record ${e.record}: ${e.message}`} />
                ))}
                <div className="portal-transfer-preview">
                  {preview.documents.slice(0, 10).map((d, i) => (
                    <div key={i} className="portal-shell-doc">
                      <DocumentView doc={d} expandDepth={1} />
                    </div>
                  ))}
                </div>
              </>
            )}
          </CardBody>
        </Card>
      </GridItem>
    </Grid>
  );
}

const stateLabel: Record<Job['state'], { color: 'blue' | 'green' | 'red' | 'grey' | 'orange'; icon: React.ReactNode; text: string }> = {
  queued: { color: 'grey', icon: <InProgressIcon />, text: 'Queued' },
  running: { color: 'blue', icon: <InProgressIcon />, text: 'Running' },
  succeeded: { color: 'green', icon: <CheckCircleIcon />, text: 'Succeeded' },
  failed: { color: 'red', icon: <ExclamationCircleIcon />, text: 'Failed' },
  cancelled: { color: 'orange', icon: <BanIcon />, text: 'Cancelled' },
};

function JobsPanel() {
  const jobs = useJobs();
  const cancel = useCancelJob();
  const list = jobs.data?.jobs ?? [];
  if (jobs.isPending) return null;
  if (list.length === 0) return <Content component="p">No import jobs yet. Jobs are kept for an hour after they finish.</Content>;
  return (
    <>
      <Content component="small">{jobs.data?.note}</Content>
      {list.map((j) => {
        const s = stateLabel[j.state];
        const running = j.state === 'queued' || j.state === 'running';
        const pct = j.fileBytes > 0 ? Math.min(100, (j.processedBytes / j.fileBytes) * 100) : 0;
        return (
          <Card key={j.id} isCompact className="pf-v6-u-mt-md">
            <CardBody>
              <Flex alignItems={{ default: 'alignItemsCenter' }} gap={{ default: 'gapMd' }}>
                <Label color={s.color} icon={s.icon}>
                  {s.text}
                </Label>
                <strong className="portal-mono">
                  {j.database}.{j.collection}
                </strong>
                <span className="portal-muted">
                  {j.fileName || 'upload'} · {formatBytes(j.fileBytes)} · {j.format} · {j.mode}
                  {j.dryRun ? ' · dry run' : ''}
                </span>
                <FlexItem align={{ default: 'alignRight' }}>
                  {running && (
                    <Button variant="secondary" size="sm" onClick={() => cancel.mutate(j.id)}>
                      Cancel
                    </Button>
                  )}
                  {j.failed > 0 && (
                    <Button variant="link" size="sm" component="a" href={`/api/v1/jobs/${encodeURIComponent(j.id)}/errors`} download icon={<DownloadIcon />}>
                      Rejected records
                    </Button>
                  )}
                </FlexItem>
              </Flex>
              {running && <Progress className="pf-v6-u-mt-sm" value={pct} size={ProgressSize.sm} aria-label="Import progress" measureLocation="outside" label={`${pct.toFixed(0)}%`} />}
              <Flex className="pf-v6-u-mt-sm" gap={{ default: 'gapLg' }}>
                <span>
                  <strong>{j.read.toLocaleString()}</strong> read
                </span>
                <span>
                  <strong>{(j.inserted + j.upserted).toLocaleString()}</strong> {j.mode === 'upsert' ? 'inserted' : 'written'}
                </span>
                {j.mode === 'upsert' && (
                  <span>
                    <strong>{j.matched.toLocaleString()}</strong> replaced
                  </span>
                )}
                <span className={j.failed ? 'portal-status-danger' : undefined}>
                  <strong>{j.failed.toLocaleString()}</strong> rejected
                </span>
              </Flex>
              {j.message && <Alert className="pf-v6-u-mt-sm" variant={j.state === 'failed' ? 'danger' : 'info'} isInline isPlain title={j.message} />}
              <ExpandableSection toggleText="Details" className="pf-v6-u-mt-sm">
                <Content component="small">SHA-256 of the uploaded file</Content>
                <ClipboardCopy isReadOnly hoverTip="Copy" clickTip="Copied" variant="inline-compact">
                  {j.sha256}
                </ClipboardCopy>
                {j.errors.length > 0 && (
                  <Table aria-label="Rejected records" variant="compact" className="pf-v6-u-mt-sm">
                    <Thead>
                      <Tr>
                        <Th>Record</Th>
                        <Th>Code</Th>
                        <Th>Message</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {j.errors.map((e, i) => (
                        <Tr key={i}>
                          <Td>{e.record}</Td>
                          <Td>{e.code ?? '—'}</Td>
                          <Td>{e.message}</Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                )}
              </ExpandableSection>
            </CardBody>
          </Card>
        );
      })}
    </>
  );
}

export function TransferPage({ me }: { me: Me }) {
  const [params, setParams] = useSearchParams();
  const db = params.get('db') ?? '';
  const coll = params.get('coll') ?? '';
  const [tab, setTab] = useState<string | number>(params.get('tab') ?? 'export');
  const set = useMemo(
    () => (k: string, v: string) => {
      const n = new URLSearchParams(params);
      if (v) n.set(k, v);
      else n.delete(k);
      if (k === 'db') n.delete('coll');
      setParams(n, { replace: true });
    },
    [params, setParams],
  );
  return (
    <PageSection>
      <Title headingLevel="h1" className="pf-v6-u-mb-sm">
        Import &amp; export
      </Title>
      <Content component="p" className="portal-shell-intro pf-v6-u-mb-md">
        Move data in and out of collections with your own MongoDB privileges. Exports stream to your browser; imports run in the background
        and report every rejected document.
      </Content>
      <Card className="pf-v6-u-mb-md">
        <CardBody>
          <NamespacePicker db={db} coll={coll} onDb={(v) => set('db', v)} onColl={(v) => set('coll', v)} />
        </CardBody>
      </Card>
      <Tabs activeKey={tab} onSelect={(_e, k) => setTab(k)} aria-label="Import and export" mountOnEnter>
        <Tab eventKey="export" title={<TabTitleText>Export</TabTitleText>}>
          <div className="pf-v6-u-pt-md">
            <ExportPanel me={me} db={db} coll={coll} />
          </div>
        </Tab>
        <Tab eventKey="import" title={<TabTitleText>Import</TabTitleText>}>
          <div className="pf-v6-u-pt-md">
            <ImportPanel me={me} db={db} coll={coll} onStarted={() => setTab('jobs')} />
          </div>
        </Tab>
        <Tab eventKey="jobs" title={<TabTitleText>Jobs</TabTitleText>}>
          <div className="pf-v6-u-pt-md">
            <JobsPanel />
          </div>
        </Tab>
      </Tabs>
    </PageSection>
  );
}
