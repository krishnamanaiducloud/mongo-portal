import { useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  ClipboardCopy,
  Content,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  EmptyState,
  EmptyStateBody,
  FormSelect,
  FormSelectOption,
  Grid,
  GridItem,
  Label,
  LabelGroup,
  PageSection,
  Spinner,
  ToggleGroup,
  ToggleGroupItem,
} from '@patternfly/react-core';
import { CheckCircleIcon, ExclamationCircleIcon, ExclamationTriangleIcon, InfoCircleIcon, LightbulbIcon, PlayIcon } from '@patternfly/react-icons';
import { useAdvisor, useDatabases } from '../api/hooks';
import type { AdvisorFinding } from '../api/types';
import { PageHeader } from '../components/PageHeader';
import { ErrorState } from './StatusPages';

const severityLabel: Record<AdvisorFinding['severity'], { color: 'red' | 'orange' | 'blue'; icon: React.ReactNode; text: string }> = {
  critical: { color: 'red', icon: <ExclamationCircleIcon />, text: 'Critical' },
  warning: { color: 'orange', icon: <ExclamationTriangleIcon />, text: 'Warning' },
  info: { color: 'blue', icon: <InfoCircleIcon />, text: 'Info' },
};

const kindText: Record<string, string> = {
  missing_index: 'Missing index',
  inefficient_index: 'Inefficient index',
  in_memory_sort: 'In-memory sort',
  redundant_index: 'Redundant index',
  unused_index: 'Unused index',
  many_indexes: 'Many indexes',
  large_documents: 'Large documents',
  no_secondary_index: 'No secondary index',
  no_constraints: 'Constraints',
};

const evidenceText: Record<string, string> = {
  occurrences: 'Seen',
  avgMillis: 'Average time (ms)',
  avgDocsExamined: 'Documents examined (avg)',
  avgKeysExamined: 'Index keys examined (avg)',
  avgReturned: 'Documents returned (avg)',
  plan: 'Plan',
  query: 'Query shape',
  sort: 'Sort',
  index: 'Index',
  coveredBy: 'Covered by',
  since: 'Unused since',
  indexes: 'Indexes',
  avgObjSize: 'Average document size (bytes)',
  documents: 'Documents',
  collections: 'Collections',
  total: 'Total',
};

const sourceColor = { available: 'green', partial: 'orange', unavailable: 'grey', off: 'grey' } as const;

function evidenceValue(v: unknown): string {
  if (Array.isArray(v)) return v.join(', ');
  if (typeof v === 'number') return v.toLocaleString();
  return String(v);
}

function FindingCard({ f }: { f: AdvisorFinding }) {
  const sev = severityLabel[f.severity];
  const evidence = Object.entries(f.evidence ?? {}).filter(([k, v]) => v !== '' && v !== '{}' && !(k === 'avgKeysExamined' && v === 0));
  return (
    <Card className={`portal-finding is-${f.severity}`} isCompact>
      <CardHeader>
        <CardTitle>
          <LabelGroup>
            <Label color={sev.color} icon={sev.icon} isCompact>
              {sev.text}
            </Label>
            <Label isCompact>{kindText[f.kind] ?? f.kind}</Label>
            <Label isCompact variant="outline" className="portal-mono">
              {f.namespace}
            </Label>
          </LabelGroup>
          <div className="portal-finding-title">{f.title}</div>
        </CardTitle>
      </CardHeader>
      <CardBody>
        <Content component="p">{f.detail}</Content>
        {evidence.length > 0 && (
          <DescriptionList isCompact isHorizontal className="pf-v6-u-mt-sm" columnModifier={{ default: '1Col', lg: '2Col' }}>
            {evidence.map(([k, v]) => (
              <DescriptionListGroup key={k}>
                <DescriptionListTerm>{evidenceText[k] ?? k}</DescriptionListTerm>
                <DescriptionListDescription className={k === 'query' || k === 'sort' || k === 'plan' || k === 'index' || k === 'coveredBy' ? 'portal-mono' : undefined}>
                  {evidenceValue(v)}
                </DescriptionListDescription>
              </DescriptionListGroup>
            ))}
          </DescriptionList>
        )}
        {f.suggestion && (
          <div className="pf-v6-u-mt-md">
            <ClipboardCopy isReadOnly isCode hoverTip="Copy" clickTip="Copied" variant={f.suggestion.includes('\n') ? 'expansion' : 'inline-compact'}>
              {f.suggestion}
            </ClipboardCopy>
            <Content component="small" className="portal-muted">
              Review before running it in the shell. The advisor never runs commands.
            </Content>
          </div>
        )}
      </CardBody>
    </Card>
  );
}

export function AdvisorPage() {
  const [db, setDb] = useState('');
  const [show, setShow] = useState<'all' | AdvisorFinding['severity']>('all');
  const dbs = useDatabases();
  const q = useAdvisor(db);
  const rep = q.data;
  const counts = useMemo(() => {
    const c = { critical: 0, warning: 0, info: 0 };
    for (const f of rep?.findings ?? []) c[f.severity]++;
    return c;
  }, [rep]);
  const findings = (rep?.findings ?? []).filter((f) => show === 'all' || f.severity === show);
  const userDbs = (dbs.data?.databases ?? []).filter((d) => !['admin', 'local', 'config'].includes(d.name));

  return (
    <PageSection>
      <PageHeader
        icon={<LightbulbIcon />}
        title="Performance advisor"
        description="Finds full collection scans, missing, redundant and unused indexes, in-memory sorts and missing constraints. It only reads, with your own MongoDB privileges; queries are shown as shapes, never with their values."
        actions={
          <>
            <FormSelect aria-label="Database" value={db} onChange={(_e, v) => setDb(v)} className="portal-advisor-db">
              <FormSelectOption value="" label="All databases" />
              {userDbs.map((d) => (
                <FormSelectOption key={d.name} value={d.name} label={d.name} />
              ))}
            </FormSelect>
            <Button icon={<PlayIcon />} onClick={() => void q.refetch()} isLoading={q.isFetching} isDisabled={q.isFetching}>
              {rep ? 'Analyze again' : 'Analyze'}
            </Button>
          </>
        }
      />
      {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}
      {!rep && !q.isFetching && !q.isError && (
        <EmptyState titleText="Analyze this deployment" icon={LightbulbIcon} headingLevel="h2">
          <EmptyStateBody>
            Choose a database or all databases and select <strong>Analyze</strong>. The analysis reads index definitions and usage, collection statistics,
            the profiler (where a database administrator enabled it) and the server's recent slow-query log. It changes nothing.
          </EmptyStateBody>
        </EmptyState>
      )}
      {q.isFetching && !rep && (
        <Content component="p">
          <Spinner size="md" aria-hidden /> Reading indexes, statistics and recent slow operations…
        </Content>
      )}
      {rep && (
        <>
          <Grid hasGutter className="pf-v6-u-mb-lg">
            {(['critical', 'warning', 'info'] as const).map((s) => (
              <GridItem key={s} md={3} sm={6}>
                <Card isCompact isClickable isSelectable isSelected={show === s} className={`portal-advisor-tile is-${s}`}>
                  <CardHeader selectableActions={{ onClickAction: () => setShow(show === s ? 'all' : s), selectableActionAriaLabel: `Show ${s} findings` }}>
                    <div className="portal-stat-label">{severityLabel[s].text}</div>
                    <div className="portal-stat-value">{counts[s]}</div>
                  </CardHeader>
                </Card>
              </GridItem>
            ))}
            <GridItem md={3} sm={6}>
              <Card isCompact>
                <CardHeader>
                  <div className="portal-stat-label">Scanned</div>
                  <div className="portal-stat-sub">
                    {rep.scanned.databases ?? 0} databases · {rep.scanned.collections ?? 0} collections · {rep.scanned.queries ?? 0} recent queries · {rep.duration}
                  </div>
                </CardHeader>
              </Card>
            </GridItem>
          </Grid>
          {rep.truncated && (
            <Alert className="pf-v6-u-mb-md" isInline variant="info" title="Partial analysis">
              Large deployments are analyzed up to 50 databases and 300 collections per run. Choose one database to analyze the rest.
            </Alert>
          )}
          <Card className="pf-v6-u-mb-lg" isCompact>
            <CardTitle>What the analysis could read</CardTitle>
            <CardBody>
              <ul className="portal-advisor-sources">
                {rep.sources.map((s) => (
                  <li key={s.name}>
                    <Label color={sourceColor[s.state]} isCompact>
                      {s.state}
                    </Label>
                    <strong>{s.name}</strong>
                    {s.detail && <span className="portal-muted"> — {s.detail}</span>}
                  </li>
                ))}
              </ul>
            </CardBody>
          </Card>
          <div className="portal-toolbar-row pf-v6-u-mb-md">
            <ToggleGroup aria-label="Severity">
              {(['all', 'critical', 'warning', 'info'] as const).map((s) => (
                <ToggleGroupItem key={s} text={s === 'all' ? `All (${rep.findings.length})` : `${severityLabel[s].text} (${counts[s]})`} isSelected={show === s} onChange={() => setShow(s)} />
              ))}
            </ToggleGroup>
          </div>
          {findings.length === 0 ? (
            <EmptyState titleText="No findings" icon={CheckCircleIcon} headingLevel="h2">
              <EmptyStateBody>
                {rep.findings.length === 0
                  ? 'Nothing to improve was found in what the analysis could read. Enable the profiler for slow operations to give the advisor more to work with.'
                  : 'No findings of this severity.'}
              </EmptyStateBody>
            </EmptyState>
          ) : (
            <div className="portal-findings">
              {findings.map((f, i) => (
                <FindingCard key={`${f.kind}-${f.namespace}-${i}`} f={f} />
              ))}
            </div>
          )}
        </>
      )}
    </PageSection>
  );
}
