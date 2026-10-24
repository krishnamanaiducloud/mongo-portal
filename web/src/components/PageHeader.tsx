import type { ReactNode } from 'react';
import { Title } from '@patternfly/react-core';

/** A page title with an optional icon, description and actions. */
export function PageHeader({ title, description, icon, actions }: { title: ReactNode; description?: ReactNode; icon?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="portal-page-header">
      <div className="portal-page-header-text">
        {icon && (
          <span className="portal-page-icon" aria-hidden>
            {icon}
          </span>
        )}
        <div>
          <Title headingLevel="h1" size="2xl">
            {title}
          </Title>
          {description && <p className="portal-page-desc">{description}</p>}
        </div>
      </div>
      {actions && <div className="portal-page-actions">{actions}</div>}
    </header>
  );
}
