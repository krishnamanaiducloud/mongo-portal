import type { ReactNode } from 'react';
import { Label, Tooltip } from '@patternfly/react-core';
import {
  CheckCircleIcon,
  DatabaseIcon,
  ExclamationTriangleIcon,
  InProgressIcon,
  MinusCircleIcon,
  OpenshiftIcon,
  OutlinedQuestionCircleIcon,
  TimesCircleIcon,
  UserIcon,
} from '@patternfly/react-icons';
import type { IdentitySource, OpenShiftStatus, ProfileHealth } from '../api/types';

const sourceText: Record<IdentitySource, string> = {
  openshift: 'Signed in with OpenShift',
  header: 'Signed in through the corporate SSO proxy',
  dev: 'Local development identity',
  mongodb: 'Signed in with MongoDB credentials only',
  '': 'Not signed in',
};

export function sourceDescription(source: IdentitySource): string {
  return sourceText[source] ?? source;
}

export function SourceIcon({ source }: { source: IdentitySource }) {
  if (source === 'openshift') return <OpenshiftIcon />;
  if (source === 'mongodb') return <DatabaseIcon />;
  return <UserIcon />;
}

/** Who the user is and how they signed in. */
export function IdentityLabel({ user, source }: { user: string; source: IdentitySource }) {
  return (
    <Tooltip content={sourceDescription(source)}>
      <Label variant="outline" icon={<SourceIcon source={source} />}>
        {user || 'anonymous'}
      </Label>
    </Tooltip>
  );
}

const health: Record<string, { color: 'green' | 'orange' | 'red' | 'grey'; icon: ReactNode; text: string }> = {
  online: { color: 'green', icon: <CheckCircleIcon />, text: 'Online' },
  degraded: { color: 'orange', icon: <ExclamationTriangleIcon />, text: 'Degraded' },
  offline: { color: 'red', icon: <TimesCircleIcon />, text: 'Unreachable' },
  misconfigured: { color: 'red', icon: <ExclamationTriangleIcon />, text: 'Misconfigured' },
  unknown: { color: 'grey', icon: <InProgressIcon />, text: 'Checking…' },
  disabled: { color: 'grey', icon: <MinusCircleIcon />, text: 'Not monitored' },
};

/** Background health of a connection profile (checked without credentials). */
export function HealthLabel({ h, compact = true }: { h?: ProfileHealth; compact?: boolean }) {
  const v = health[h?.state ?? 'unknown'] ?? health.unknown;
  const detail = [
    h?.reason,
    h?.latencyMs !== undefined && h.state === 'online' ? `${h.latencyMs} ms` : undefined,
    h?.setName ? `replica set ${h.setName}` : undefined,
    h?.checkedAt ? `checked ${new Date(h.checkedAt).toLocaleTimeString()}` : undefined,
  ]
    .filter(Boolean)
    .join(' · ');
  return (
    <Tooltip content={detail || v.text}>
      <Label isCompact={compact} color={v.color} icon={v.icon}>
        {v.text}
        {h?.state === 'online' && h.latencyMs !== undefined ? ` · ${h.latencyMs} ms` : ''}
      </Label>
    </Tooltip>
  );
}

const osState: Record<OpenShiftStatus['state'], { color: 'green' | 'orange' | 'grey'; icon: ReactNode; text: string }> = {
  available: { color: 'green', icon: <CheckCircleIcon />, text: 'Available' },
  unavailable: { color: 'orange', icon: <ExclamationTriangleIcon />, text: 'Unavailable' },
  disabled: { color: 'grey', icon: <OutlinedQuestionCircleIcon />, text: 'Not offered' },
};

export function OpenShiftStateLabel({ s }: { s: OpenShiftStatus }) {
  const v = osState[s.state] ?? osState.disabled;
  return (
    <Tooltip content={s.reason || (s.issuer ? `OAuth server ${s.issuer}` : v.text)}>
      <Label isCompact color={v.color} icon={v.icon}>
        {v.text}
      </Label>
    </Tooltip>
  );
}
