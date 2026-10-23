import type { ReactNode } from 'react';
import { Label, LabelGroup, Tooltip } from '@patternfly/react-core';
import { DatabaseIcon, EyeIcon, PencilAltIcon, UserShieldIcon, UsersIcon } from '@patternfly/react-icons';
import type { Access, PortalAccess } from '../api/types';

const builtinRoleText: Record<string, { label: string; color: 'purple' | 'orange' | 'blue' | 'teal'; help: string }> = {
  'role:admin': { label: 'Admin', color: 'purple', help: 'role:admin — everything the portal offers, up to your MongoDB privileges' },
  'role:editor': { label: 'Editor', color: 'orange', help: 'role:editor — read, plus document and index changes and creating collections' },
  'role:readonly': { label: 'Read-only', color: 'blue', help: 'role:readonly — browse, query and use the shell without writes' },
  'role:mongodb': { label: 'MongoDB roles', color: 'teal', help: 'role:mongodb — follows your MongoDB privileges: what MongoDB allows, the portal allows' },
};

/** The highest built-in role among roles, used for compact labels. */
export function primaryRole(roles: string[]): string | undefined {
  return ['role:admin', 'role:mongodb', 'role:editor', 'role:readonly'].find((r) => roles.includes(r)) ?? roles[0];
}

/** Portal RBAC roles of the current user. */
export function RolesLabel({ roles, compact }: { roles: string[]; compact?: boolean }) {
  if (roles.length === 0) {
    return (
      <Tooltip content="No portal role: the RBAC policy grants you nothing. Ask an administrator to map your user or group.">
        <Label color="red" isCompact={compact}>
          No access
        </Label>
      </Tooltip>
    );
  }
  if (compact) {
    const main = primaryRole(roles)!;
    const known = builtinRoleText[main];
    const others = roles.filter((r) => r !== main && !builtinRoleText[r]);
    return (
      <Tooltip content={`Portal roles: ${roles.join(', ')}`}>
        <Label color={known?.color ?? 'grey'} icon={main === 'role:admin' ? <UserShieldIcon /> : main === 'role:readonly' ? <EyeIcon /> : main === 'role:mongodb' ? <DatabaseIcon /> : <UsersIcon />}>
          {known?.label ?? main.replace(/^role:/, '')}
          {others.length > 0 ? ` +${others.length}` : ''}
        </Label>
      </Tooltip>
    );
  }
  return (
    <LabelGroup numLabels={6}>
      {roles.map((r) => {
        const known = builtinRoleText[r];
        return (
          <Tooltip key={r} content={known?.help ?? `${r} — defined by the portal RBAC policy`}>
            <Label isCompact color={known?.color ?? 'grey'}>
              {r}
            </Label>
          </Tooltip>
        );
      })}
    </LabelGroup>
  );
}

export type WriteAction = keyof Pick<
  PortalAccess,
  'insert' | 'update' | 'remove' | 'createIndex' | 'dropIndex' | 'createCollection' | 'dropCollection'
>;

/**
 * UI hint only: whether to offer an action. It is offered when the portal
 * RBAC policy and the MongoDB privileges of the session both allow it. The
 * backend enforces RBAC on every request and MongoDB enforces privileges.
 */
export function canDo(access: Access | undefined, action: WriteAction): boolean {
  if (!access) return false;
  const portal = access.portal ? access.portal[action] : access.portalWrite;
  return portal && access.mongo[action];
}

export function IfAllowed({ access, action, children }: { access?: Access; action: WriteAction; children: ReactNode }) {
  return canDo(access, action) ? <>{children}</> : null;
}

export function AccessLabel({ access }: { access?: Access }) {
  if (!access) return null;
  const m = access.mongo;
  const p = access.portal;
  const portalWrite = p ? p.insert || p.update || p.remove : access.portalWrite;
  const mongoWrite = m.insert || m.update || m.remove;
  if (portalWrite && mongoWrite) {
    return (
      <Tooltip content="Your portal role and MongoDB privileges allow modifying data here">
        <Label color="orange" icon={<PencilAltIcon />}>
          Read / write
        </Label>
      </Tooltip>
    );
  }
  const readable = (p ? p.find : true) && m.find;
  const why = !portalWrite ? 'Your portal role does not allow changes here' : 'Your MongoDB user has no write privileges here';
  return (
    <Tooltip content={why}>
      <Label color="blue" icon={<EyeIcon />}>
        {readable ? 'Read only' : 'Limited'}
      </Label>
    </Tooltip>
  );
}
