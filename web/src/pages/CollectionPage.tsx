import { useState } from 'react';
import { NavLink, useParams } from 'react-router';
import { Breadcrumb, BreadcrumbItem, Button, Flex, FlexItem, PageSection, Tab, TabTitleText, Tabs, Title } from '@patternfly/react-core';
import { DownloadIcon, ExchangeAltIcon } from '@patternfly/react-icons';
import { useCollections } from '../api/hooks';
import { AccessLabel } from '../components/Permission';
import { DocumentsTab } from './collection/DocumentsTab';
import { QueryTab } from './collection/QueryTab';
import { IndexesTab } from './collection/IndexesTab';
import { StatsTab } from './collection/StatsTab';

export function CollectionPage() {
  const { db = '', coll = '' } = useParams();
  const [tab, setTab] = useState<string | number>('documents');
  const colls = useCollections(db);
  const access = colls.data?.collections.find((c) => c.name === coll)?.access;

  return (
    <PageSection key={`${db}/${coll}`}>
      <Breadcrumb className="pf-v6-u-mb-md">
        <BreadcrumbItem render={() => <NavLink to="/databases">Databases</NavLink>} />
        <BreadcrumbItem render={() => <NavLink to={`/db/${encodeURIComponent(db)}`}>{db}</NavLink>} />
        <BreadcrumbItem isActive>{coll}</BreadcrumbItem>
      </Breadcrumb>
      <Flex alignItems={{ default: 'alignItemsCenter' }} className="pf-v6-u-mb-md">
        <Title headingLevel="h1">{coll}</Title>
        <AccessLabel access={access} />
        <FlexItem align={{ default: 'alignRight' }}>
          <Button variant="link" icon={<DownloadIcon />} component="a" href={`/api/v1/databases/${encodeURIComponent(db)}/collections/${encodeURIComponent(coll)}/export?format=ndjson`} download>
            Export
          </Button>
          <Button variant="link" icon={<ExchangeAltIcon />} component={(props: object) => <NavLink {...props} to={`/transfer?db=${encodeURIComponent(db)}&coll=${encodeURIComponent(coll)}&tab=import`} />}>
            Import &amp; export…
          </Button>
        </FlexItem>
      </Flex>
      <Tabs activeKey={tab} onSelect={(_e, k) => setTab(k)} aria-label="Collection views" mountOnEnter unmountOnExit>
        <Tab eventKey="documents" title={<TabTitleText>Documents</TabTitleText>}>
          <DocumentsTab db={db} coll={coll} />
        </Tab>
        <Tab eventKey="query" title={<TabTitleText>Query console</TabTitleText>}>
          <QueryTab db={db} coll={coll} />
        </Tab>
        <Tab eventKey="indexes" title={<TabTitleText>Indexes</TabTitleText>}>
          <IndexesTab db={db} coll={coll} />
        </Tab>
        <Tab eventKey="stats" title={<TabTitleText>Statistics</TabTitleText>}>
          <StatsTab db={db} coll={coll} />
        </Tab>
      </Tabs>
    </PageSection>
  );
}
