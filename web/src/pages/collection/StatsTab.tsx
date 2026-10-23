import {
  Alert,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Spinner,
  Stack,
} from '@patternfly/react-core';
import { useCollectionStats } from '../../api/hooks';
import { formatBytes, num } from '../../lib/ejson';
import { ErrorState } from '../StatusPages';

const fields: [string, string, boolean][] = [
  ['count', 'Documents', false],
  ['size', 'Data size', true],
  ['avgObjSize', 'Average document size', true],
  ['storageSize', 'Storage size', true],
  ['nindexes', 'Indexes', false],
  ['totalIndexSize', 'Total index size', true],
  ['totalSize', 'Total size', true],
];

export function StatsTab({ db, coll }: { db: string; coll: string }) {
  const st = useCollectionStats(db, coll);
  if (st.isPending) return <Spinner aria-label="Loading statistics" />;
  if (st.isError) return <ErrorState error={st.error} onRetry={() => void st.refetch()} />;
  const s = st.data.stats;
  return (
    <Stack hasGutter className="pf-v6-u-pt-md">
      {st.data.limited && (
        <Alert variant="info" isInline isPlain title="Your MongoDB user cannot read storage statistics; showing the estimated document count only." />
      )}
      <DescriptionList isHorizontal columnModifier={{ default: '1Col', md: '2Col' }}>
        {fields
          .filter(([k]) => s[k] !== undefined)
          .map(([k, label, bytes]) => (
            <DescriptionListGroup key={k}>
              <DescriptionListTerm>{label}</DescriptionListTerm>
              <DescriptionListDescription>{bytes ? formatBytes(num(s[k])) : String(num(s[k]) ?? '—')}</DescriptionListDescription>
            </DescriptionListGroup>
          ))}
        {s.capped !== undefined && (
          <DescriptionListGroup>
            <DescriptionListTerm>Capped</DescriptionListTerm>
            <DescriptionListDescription>{String(s.capped)}</DescriptionListDescription>
          </DescriptionListGroup>
        )}
      </DescriptionList>
    </Stack>
  );
}
