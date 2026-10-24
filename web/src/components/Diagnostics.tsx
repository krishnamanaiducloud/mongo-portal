import { Alert, Button, Content, Spinner } from '@patternfly/react-core';
import { CheckCircleIcon, ExclamationCircleIcon, ExclamationTriangleIcon, MinusCircleIcon, StethoscopeIcon } from '@patternfly/react-icons';
import { errorMessage } from '../api/client';
import { useProfileDiagnostics } from '../api/hooks';
import type { CheckStatus } from '../api/types';

const icons: Record<CheckStatus, React.ReactNode> = {
  pass: <CheckCircleIcon className="portal-status-success" />,
  warn: <ExclamationTriangleIcon className="portal-status-warning" />,
  fail: <ExclamationCircleIcon className="portal-status-danger" />,
  skip: <MinusCircleIcon className="portal-muted" />,
};

/** Read-only connection checks of one profile: DNS, TCP, TLS, topology,
 * version and, for MONGODB-OIDC, the identity provider MongoDB trusts. */
export function DiagnosticsPanel({ profile, label = 'Diagnose connection', compact }: { profile: string; label?: string; compact?: boolean }) {
  const diag = useProfileDiagnostics();
  const rep = diag.data;
  return (
    <div className="portal-diag">
      <Button
        variant={compact ? 'link' : 'secondary'}
        isInline={compact}
        icon={<StethoscopeIcon />}
        onClick={() => diag.mutate(profile)}
        isLoading={diag.isPending}
        isDisabled={diag.isPending}
      >
        {rep ? 'Run again' : label}
      </Button>
      {diag.isPending && (
        <Content component="small" className="portal-muted pf-v6-u-ml-sm">
          <Spinner size="sm" aria-hidden /> Checking name resolution, network, TLS and MongoDB…
        </Content>
      )}
      {diag.isError && <Alert className="pf-v6-u-mt-sm" variant="warning" isInline isPlain title={errorMessage(diag.error)} />}
      {rep && (
        <>
          <ul className="portal-diag-list" aria-label="Connection diagnostics">
            {rep.results.map((r, i) => (
              <li key={i} className={`is-${r.status}`}>
                <span className="portal-diag-icon" aria-label={r.status}>
                  {icons[r.status]}
                </span>
                <span className="portal-diag-check">
                  {r.check}
                  {r.target && <span className="portal-diag-target">{r.target}</span>}
                </span>
                <span className="portal-diag-detail">{r.detail}</span>
              </li>
            ))}
          </ul>
          <Content component="small" className="portal-muted">
            {rep.summary.pass} passed · {rep.summary.warn} warnings · {rep.summary.fail} failed · {rep.duration}. Nothing was changed and no credentials were sent.
          </Content>
        </>
      )}
    </div>
  );
}
