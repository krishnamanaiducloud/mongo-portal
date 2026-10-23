import { useMemo, useState } from 'react';
import {
  Alert,
  Card,
  CardBody,
  CardTitle,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Flex,
  FlexItem,
  FormSelect,
  FormSelectOption,
  Grid,
  GridItem,
  Label,
  LabelGroup,
  PageSection,
  SearchInput,
  Spinner,
  TextInput,
  Title,
} from '@patternfly/react-core';
import { CheckCircleIcon, TimesCircleIcon } from '@patternfly/react-icons';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { usePermissions, type AccessCheck } from '../api/hooks';
import { IdentityLabel, sourceDescription } from '../components/Indicators';
import { RolesLabel } from '../components/Permission';
import { ErrorState } from './StatusPages';

const actions: Record<string, string[]> = {
  documents: ['get', 'create', 'update', 'delete'],
  collections: ['get', 'create', 'update', 'delete'],
  indexes: ['get', 'create', 'delete'],
  databases: ['get', 'delete'],
  shell: ['use', 'admin'],
  server: ['get'],
  audit: ['get'],
};

const objectHint: Record<string, string> = {
  documents: 'database/collection',
  collections: 'database/collection',
  indexes: 'database/collection',
  databases: 'database',
  shell: '* or database (admin)',
  server: 'profile name',
  audit: 'self or all',
};

export function PermissionsPage() {
  const [resource, setResource] = useState('documents');
  const [action, setAction] = useState('update');
  const [object, setObject] = useState('');
  const [filter, setFilter] = useState('');
  const check: AccessCheck | undefined = object.trim() ? { resource, action, object: object.trim() } : undefined;
  const perms = usePermissions(check);
  const p = perms.data;

  const rules = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return (p?.rules ?? []).filter((r) => !f || [r.role, r.resource, r.action, r.object, r.effect].join(' ').toLowerCase().includes(f));
  }, [p, filter]);

  if (perms.isPending) return <Spinner aria-label="Loading permissions" />;
  if (perms.isError && !p) return <ErrorState error={perms.error} onRetry={() => void perms.refetch()} />;
  if (!p) return null;

  return (
    <PageSection>
      <Title headingLevel="h1" className="pf-v6-u-mb-md">
        My permissions
      </Title>
      <Alert
        variant="info"
        isInline
        isPlain
        className="pf-v6-u-mb-md"
        title="Portal RBAC narrows what the portal offers; MongoDB still authorizes every operation with your own MongoDB user."
      />
      {p.policy.error && (
        <Alert variant="warning" isInline className="pf-v6-u-mb-md" title="The latest RBAC policy update was rejected; the previous policy is active">
          {p.policy.error}
        </Alert>
      )}
      <Grid hasGutter>
        <GridItem lg={5}>
          <Card isFullHeight>
            <CardTitle>Identity</CardTitle>
            <CardBody>
              <DescriptionList isCompact>
                <DescriptionListGroup>
                  <DescriptionListTerm>User</DescriptionListTerm>
                  <DescriptionListDescription>
                    <IdentityLabel user={p.user} source={p.source} /> <span className="pf-v6-u-font-size-sm">{sourceDescription(p.source)}</span>
                  </DescriptionListDescription>
                </DescriptionListGroup>
                <DescriptionListGroup>
                  <DescriptionListTerm>Roles</DescriptionListTerm>
                  <DescriptionListDescription>
                    <RolesLabel roles={p.roles} />
                  </DescriptionListDescription>
                </DescriptionListGroup>
                <DescriptionListGroup>
                  <DescriptionListTerm>Granted by</DescriptionListTerm>
                  <DescriptionListDescription>
                    {p.directRoles.length > 0 ? p.directRoles.join(', ') : 'no group or user mapping'}
                    {p.defaultRole ? ` · default role ${p.defaultRole}` : ' · no default role'}
                  </DescriptionListDescription>
                </DescriptionListGroup>
                <DescriptionListGroup>
                  <DescriptionListTerm>Matched as</DescriptionListTerm>
                  <DescriptionListDescription>
                    <LabelGroup numLabels={6}>
                      {p.subjects.map((s) => (
                        <Label key={s} isCompact variant="outline">
                          {s}
                        </Label>
                      ))}
                    </LabelGroup>
                  </DescriptionListDescription>
                </DescriptionListGroup>
                <DescriptionListGroup>
                  <DescriptionListTerm>Policy</DescriptionListTerm>
                  <DescriptionListDescription>
                    {p.policy.source === 'file' ? 'RBAC ConfigMap' : p.policy.source === 'config' ? 'portal configuration' : 'built-in roles only'} · loaded{' '}
                    {new Date(p.policy.loadedAt).toLocaleString()}
                  </DescriptionListDescription>
                </DescriptionListGroup>
              </DescriptionList>
            </CardBody>
          </Card>
        </GridItem>
        <GridItem lg={7}>
          <Card isFullHeight>
            <CardTitle>Check access</CardTitle>
            <CardBody>
              <Flex spaceItems={{ default: 'spaceItemsSm' }} alignItems={{ default: 'alignItemsFlexEnd' }}>
                <FlexItem>
                  <FormSelect
                    aria-label="Resource"
                    value={resource}
                    onChange={(_e, v) => {
                      setResource(v);
                      setAction(actions[v][0]);
                    }}
                  >
                    {Object.keys(actions).map((r) => (
                      <FormSelectOption key={r} value={r} label={r} />
                    ))}
                  </FormSelect>
                </FlexItem>
                <FlexItem>
                  <FormSelect aria-label="Action" value={action} onChange={(_e, v) => setAction(v)}>
                    {actions[resource].map((a) => (
                      <FormSelectOption key={a} value={a} label={a} />
                    ))}
                  </FormSelect>
                </FlexItem>
                <FlexItem grow={{ default: 'grow' }}>
                  <TextInput aria-label="Object" placeholder={objectHint[resource]} value={object} onChange={(_e, v) => setObject(v)} />
                </FlexItem>
              </Flex>
              <div className="pf-v6-u-mt-md" aria-live="polite">
                {p.check && (
                  <Label
                    color={p.check.allowed ? 'green' : 'red'}
                    icon={p.check.allowed ? <CheckCircleIcon /> : <TimesCircleIcon />}
                  >
                    {p.check.allowed ? 'Allowed' : 'Denied'} by the portal: {p.check.action} {p.check.resource} on {p.check.object}
                  </Label>
                )}
                {!p.check && <span className="pf-v6-u-font-size-sm">Enter an object (for example app/orders) to evaluate the policy.</span>}
              </div>
            </CardBody>
          </Card>
        </GridItem>
        <GridItem span={12}>
          <Card>
            <CardTitle>Rules that apply to you</CardTitle>
            <CardBody>
              <SearchInput aria-label="Filter rules" placeholder="Filter rules" value={filter} onChange={(_e, v) => setFilter(v)} onClear={() => setFilter('')} className="pf-v6-u-mb-sm" />
              <Table aria-label="RBAC rules" variant="compact">
                <Thead>
                  <Tr>
                    <Th>Role</Th>
                    <Th>Resource</Th>
                    <Th>Action</Th>
                    <Th>Object</Th>
                    <Th>Effect</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {rules.map((r, i) => (
                    <Tr key={i}>
                      <Td dataLabel="Role" className="portal-mono">{r.role}</Td>
                      <Td dataLabel="Resource">{r.resource}</Td>
                      <Td dataLabel="Action">{r.action}</Td>
                      <Td dataLabel="Object" className="portal-mono">{r.object}</Td>
                      <Td dataLabel="Effect">
                        <Label isCompact color={r.effect === 'allow' ? 'green' : 'red'}>
                          {r.effect}
                        </Label>
                      </Td>
                    </Tr>
                  ))}
                  {rules.length === 0 && (
                    <Tr>
                      <Td colSpan={5}>{p.rules.length === 0 ? 'No rules apply: the portal grants you nothing.' : 'No rules match the filter.'}</Td>
                    </Tr>
                  )}
                </Tbody>
              </Table>
            </CardBody>
          </Card>
        </GridItem>
      </Grid>
    </PageSection>
  );
}
