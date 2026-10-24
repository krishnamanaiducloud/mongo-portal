import {
  Alert,
  Bullseye,
  Button,
  EmptyState,
  EmptyStateActions,
  EmptyStateBody,
  EmptyStateFooter,
  PageSection,
} from '@patternfly/react-core';
import { BanIcon, ExclamationCircleIcon, SearchIcon } from '@patternfly/react-icons';
import { NavLink, useNavigate } from 'react-router';
import { ApiError, errorMessage } from '../api/client';
import { useSignOut } from '../api/hooks';
import type { Me, SessionInfo } from '../api/types';

export function AccessDeniedPage({ me, session }: { me: Me; session?: SessionInfo }) {
  const signOut = useSignOut();
  const navigate = useNavigate();
  const id = session?.identity ?? { user: me.user, source: me.source, groups: me.groups };
  const leave = async () => {
    try {
      await signOut.mutateAsync();
    } finally {
      navigate('/login?reason=signedout', { replace: true });
    }
  };
  return (
    <Bullseye className="pf-v6-u-h-100vh">
      <EmptyState titleText="No portal access" headingLevel="h1" icon={BanIcon} status="warning">
        <EmptyStateBody>
          You are signed in as <strong>{id.user}</strong>
          {id.source === 'mongodb' ? ' (MongoDB user)' : ''}, but the portal RBAC policy grants you no role
          {(id.groups ?? []).length > 0 ? ` for the groups ${(id.groups ?? []).join(', ')}` : ''}. Ask an administrator to map your
          {id.source === 'mongodb' ? ` MongoDB user (mongodb:${id.user})` : ' OpenShift user or group'} to a role.
        </EmptyStateBody>
        <EmptyStateFooter>
          <EmptyStateActions>
            <Button variant="secondary" onClick={() => void leave()} isLoading={signOut.isPending}>
              Sign out
            </Button>
          </EmptyStateActions>
        </EmptyStateFooter>
      </EmptyState>
    </Bullseye>
  );
}

export function ErrorPage({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return (
    <Bullseye className="pf-v6-u-h-100vh">
      <ErrorState error={error} onRetry={onRetry} />
    </Bullseye>
  );
}

/** Inline error panel. Never shows stack traces; includes the request id for support. */
export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const forbidden = error instanceof ApiError && error.status === 403;
  return (
    <EmptyState
      titleText={forbidden ? 'Not authorized' : 'Something went wrong'}
      headingLevel="h2"
      icon={forbidden ? BanIcon : ExclamationCircleIcon}
      status={forbidden ? 'warning' : 'danger'}
    >
      <EmptyStateBody>
        {errorMessage(error)}
        {error instanceof ApiError && error.requestId && (
          <div className="pf-v6-u-font-size-sm pf-v6-u-mt-sm">Request ID: {error.requestId}</div>
        )}
      </EmptyStateBody>
      {onRetry && (
        <EmptyStateFooter>
          <EmptyStateActions>
            <Button variant="secondary" onClick={onRetry}>
              Try again
            </Button>
          </EmptyStateActions>
        </EmptyStateFooter>
      )}
    </EmptyState>
  );
}

export function InlineError({ error }: { error: unknown }) {
  if (!error) return null;
  const rid = error instanceof ApiError ? error.requestId : undefined;
  return (
    <Alert variant="danger" isInline title={errorMessage(error)}>
      {rid && <span className="pf-v6-u-font-size-sm">Request ID: {rid}</span>}
    </Alert>
  );
}

export function NotFoundPage() {
  return (
    <PageSection>
      <EmptyState titleText="Page not found" headingLevel="h1" icon={SearchIcon}>
        <EmptyStateBody>The page you requested does not exist.</EmptyStateBody>
        <EmptyStateFooter>
          <NavLink to="/databases">Back to databases</NavLink>
        </EmptyStateFooter>
      </EmptyState>
    </PageSection>
  );
}
