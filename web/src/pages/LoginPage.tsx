import { useEffect, useState } from 'react';
import { Navigate, useLocation, useNavigate, useSearchParams } from 'react-router';
import {
  ActionGroup,
  Alert,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Content,
  Divider,
  ExpandableSection,
  Form,
  FormGroup,
  FormHelperText,
  FormSelect,
  FormSelectOption,
  Gallery,
  HelperText,
  HelperTextItem,
  InputGroup,
  InputGroupItem,
  Label,
  LabelGroup,
  Spinner,
  TextInput,
  Title,
} from '@patternfly/react-core';
import {
  CheckCircleIcon,
  DatabaseIcon,
  EyeIcon,
  EyeSlashIcon,
  KeyIcon,
  LockIcon,
  OpenshiftIcon,
  ShieldAltIcon,
  SignOutAltIcon,
  UnlockIcon,
  UserShieldIcon,
} from '@patternfly/react-icons';
import { ApiError, errorMessage } from '../api/client';
import { useLogin, useProfiles, useSignOut } from '../api/hooks';
import type { Me, Profile } from '../api/types';
import { DiagnosticsPanel } from '../components/Diagnostics';
import { HealthLabel, IdentityLabel, sourceDescription } from '../components/Indicators';
import { RolesLabel } from '../components/Permission';
import { browser } from '../lib/nav';
import { lastProfile, rememberProfile } from '../lib/recent';
import { ErrorState } from './StatusPages';

const reasons: Record<string, string> = {
  expired: 'Your MongoDB session expired. Connect again to continue.',
  required: 'Your MongoDB connection ended, for example because the portal restarted or moved. Connect again to continue where you were.',
  reconnect: 'Connect again to start a fresh MongoDB session.',
  logout: 'You have been disconnected from MongoDB.',
  signedout: 'You have signed out of the portal.',
};

const ssoMessages: Record<string, { title: string; body: string }> = {
  unavailable: {
    title: 'Single sign-on is not available right now',
    body: 'The identity provider could not be reached from the portal. You can still connect with your MongoDB credentials.',
  },
  failed: { title: 'Sign-in did not complete', body: 'Try again, or connect with your MongoDB credentials.' },
  denied: { title: 'Sign-in was cancelled', body: 'Access was not granted at the identity provider.' },
  expired: { title: 'The sign-in took too long', body: 'Start the sign-in again.' },
  issuer_mismatch: {
    title: 'The identity provider reports a different issuer',
    body: 'The portal is configured for another issuer URL than the provider announces. Ask the platform team to check identity.oidc.providers[].issuer.',
  },
  audience_mismatch: {
    title: 'The sign-in token was issued for another application',
    body: 'The ID token audience is not the portal client id. Ask the identity team to check the client registration.',
  },
  token_expired: { title: 'The sign-in token had already expired', body: 'Check that the clocks of the portal and the identity provider agree, then try again.' },
  not_in_group: { title: 'You are not in a group allowed to use this portal', body: 'Ask for membership in one of the portal groups.' },
  unknown_provider: { title: 'Unknown sign-in provider', body: 'Use one of the sign-in options below.' },
};

const mongoMessages: Record<string, string> = {
  oidc_not_offered: 'This connection profile does not offer MongoDB OIDC sign-in.',
  sso_required: 'Sign in with single sign-on first, then connect to MongoDB.',
  idp_unavailable: 'The identity provider of this MongoDB deployment is not reachable from the portal.',
  expired: 'The MongoDB OIDC sign-in took too long. Start it again.',
  denied: 'Access was not granted at the identity provider.',
  failed: 'The MongoDB OIDC sign-in did not complete. Try again.',
  login_required:
    'The automatic connection needs you to sign in at the identity provider, and continuing interactively is turned off for this profile. Use the button below to sign in there.',
  mongo_rejected: 'MongoDB rejected your OIDC identity. Ask a database administrator to map your identity to a MongoDB user or role.',
  mongo_oidc_failed:
    'MongoDB and this connection profile disagree about the identity provider, or MONGODB-OIDC is not enabled on the server. The diagnostics below show what the server expects.',
  token_not_jwt: 'The identity provider issued an access token MongoDB cannot use (not a JWT). Ask the identity team to issue JWT access tokens for this client.',
  token_issuer_mismatch:
    'The access token was issued by a different issuer than MongoDB trusts. For Microsoft Entra ID, the app registration must issue version 2 access tokens.',
  token_audience_mismatch: 'The access token was issued for a different audience than MongoDB expects. Ask the identity team to check the token audience for MongoDB.',
  mongo_unavailable: 'MongoDB did not respond. It may be down or unreachable from the portal.',
  tls_verification_failed: 'The MongoDB server certificate could not be verified against the configured CA.',
  rate_limited: 'Too many login attempts; try again later.',
};

// One automatic connection attempt per profile and browser within this
// window, so a failing provider never causes a redirect loop.
const AUTO_KEY = 'mongo-portal-autoconnect';
const AUTO_WINDOW_MS = 2 * 60_000;

function autoAttempted(profile: string): boolean {
  try {
    const [p, at] = (localStorage.getItem(AUTO_KEY) ?? '').split('|');
    return p === profile && Date.now() - Number(at) < AUTO_WINDOW_MS;
  } catch {
    return true;
  }
}

function markAutoAttempt(profile: string) {
  try {
    localStorage.setItem(AUTO_KEY, `${profile}|${Date.now()}`);
  } catch {
    // storage unavailable: no automatic connection
  }
}

function safeFrom(from: string | undefined) {
  return from && from.startsWith('/') && !from.startsWith('//') && from !== '/login' ? from : '/';
}

function startURL(base: string, from: string | undefined, silent = false) {
  return `${base}?return=${encodeURIComponent(safeFrom(from))}${silent ? '&silent=1' : ''}`;
}

function Steps({ signedIn }: { signedIn: boolean }) {
  return (
    <ol className="portal-steps" aria-label="Sign-in steps">
      <li className={signedIn ? 'is-done' : 'is-current'}>
        <span className="portal-step-dot">{signedIn ? <CheckCircleIcon /> : '1'}</span>
        Portal sign-in
      </li>
      <li className={signedIn ? 'is-current' : ''}>
        <span className="portal-step-dot">2</span>
        Database connection
      </li>
    </ol>
  );
}

export function LoginPage({ me }: { me: Me }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [params] = useSearchParams();
  const signOut = useSignOut();
  const from = (location.state as { from?: string } | null)?.from;
  const auth = me.auth;
  const osAvailable = auth.openshift.state === 'available';
  const oidc = (auth.oidc ?? []).filter((o) => o.state === 'available');
  const anySSO = osAvailable || oidc.length > 0;
  const ssoRequiredButMissing = auth.requireSSO && !me.sso;
  const [mongoOnly, setMongoOnly] = useState(false);
  const showMongoForm = me.sso || (auth.mongodbLogin && (!anySSO || mongoOnly));

  if (me.hasSession && !params.get('reason')) {
    return <Navigate to={safeFrom(from)} replace />;
  }

  const reason = params.get('reason');
  const sso = params.get('sso');
  const mongo = params.get('mongo');
  const failedProfile = params.get('profile') ?? '';
  const doSignOut = async () => {
    try {
      const r = await signOut.mutateAsync();
      if (r.ssoLogoutURL) {
        window.location.assign(r.ssoLogoutURL);
        return;
      }
    } catch {
      // sign-out is best effort; the page reloads the identity either way
    }
    navigate('/login?reason=signedout', { replace: true });
  };

  return (
    <div className="portal-login">
      <section className="portal-login-hero" aria-label="About the portal">
        <div className="portal-login-hero-inner">
          <div className="portal-logo-mark portal-logo-mark-lg" aria-hidden>
            <DatabaseIcon />
          </div>
          <Title headingLevel="h1" size="3xl" className="portal-login-title">
            MongoDB Portal
          </Title>
          {me.environment && <span className="portal-env-pill">{me.environment}</span>}
          <Content component="p" className="portal-login-tagline">
            Browse, query and operate MongoDB with your own identity.
          </Content>
          <ul className="portal-login-points">
            <li>
              <UserShieldIcon />
              <span>
                <strong>Single sign-on</strong>
                <br />
                OpenShift or your corporate identity provider
              </span>
            </li>
            <li>
              <KeyIcon />
              <span>
                <strong>Your own database identity</strong>
                <br />
                MongoDB OIDC or your MongoDB user; nothing is stored
              </span>
            </li>
            <li>
              <ShieldAltIcon />
              <span>
                <strong>Governed access</strong>
                <br />
                Role-based permissions and a tamper-evident audit trail
              </span>
            </li>
          </ul>
        </div>
      </section>

      <main className="portal-login-main">
        <Card className="portal-login-card" isLarge>
          <CardHeader>
            <CardTitle>
              {anySSO || me.sso ? <Steps signedIn={me.sso} /> : null}
              <Title headingLevel="h2" size="2xl">
                {me.sso ? 'Connect to MongoDB' : 'Sign in'}
              </Title>
            </CardTitle>
          </CardHeader>
          <CardBody>
            {reason && reasons[reason] && <Alert className="pf-v6-u-mb-md" variant="info" isInline isPlain title={reasons[reason]} />}
            {sso && ssoMessages[sso] && (
              <Alert className="pf-v6-u-mb-md" variant="warning" isInline title={ssoMessages[sso].title}>
                {auth.mongodbLogin ? ssoMessages[sso].body : 'Try again in a moment.'}
              </Alert>
            )}
            {mongo && (
              <Alert className="pf-v6-u-mb-md" variant="warning" isInline title="The MongoDB connection did not complete">
                <p>{mongoMessages[mongo] ?? 'Try again, or connect with a username and password where the profile allows it.'}</p>
                {me.authenticated && failedProfile && (
                  <div className="pf-v6-u-mt-sm">
                    <DiagnosticsPanel profile={failedProfile} compact />
                  </div>
                )}
              </Alert>
            )}

            {me.sso ? (
              <div className="portal-login-identity">
                <CheckCircleIcon className="portal-ok" />
                <div>
                  <div>
                    {sourceDescription(me.source)} as <IdentityLabel user={me.user} source={me.source} />
                  </div>
                  <div className="pf-v6-u-mt-xs">
                    <RolesLabel roles={me.roles} />
                  </div>
                </div>
                <Button variant="link" icon={<SignOutAltIcon />} onClick={() => void doSignOut()} isLoading={signOut.isPending}>
                  Sign out
                </Button>
              </div>
            ) : (
              <>
                {osAvailable && (
                  <Button variant="primary" size="lg" isBlock icon={<OpenshiftIcon />} component="a" href={startURL(auth.openshiftURL, from)} className="portal-sso-button">
                    Log in with OpenShift
                  </Button>
                )}
                {oidc.map((o) => (
                  <Button
                    key={o.name}
                    variant={osAvailable ? 'secondary' : 'primary'}
                    size="lg"
                    isBlock
                    icon={<KeyIcon />}
                    component="a"
                    href={startURL(o.url, from)}
                    className="portal-sso-button pf-v6-u-mt-sm"
                  >
                    Sign in with {o.displayName}
                  </Button>
                ))}
                {(auth.oidc ?? [])
                  .filter((o) => o.state !== 'available')
                  .map((o) => (
                    <HelperText key={o.name} className="pf-v6-u-mt-sm">
                      <HelperTextItem variant="indeterminate">
                        {o.displayName} is not available right now{o.reason ? ` (${o.reason})` : ''}.
                      </HelperTextItem>
                    </HelperText>
                  ))}
                {ssoRequiredButMissing && !anySSO && (
                  <Alert variant="info" isInline title="Single sign-on is required">
                    This portal accepts only single sign-on, which is not available right now
                    {auth.openshift.reason ? ` (${auth.openshift.reason})` : ''}. It is checked again automatically; reload the page in a moment.
                  </Alert>
                )}
                {anySSO && auth.mongodbLogin && !mongoOnly && (
                  <div className="portal-login-alt">
                    <Divider className="pf-v6-u-my-md" />
                    <Button variant="link" icon={<DatabaseIcon />} onClick={() => setMongoOnly(true)}>
                      Sign in with MongoDB credentials only
                    </Button>
                  </div>
                )}
                {!osAvailable && auth.mongodbLogin && auth.openshift.state === 'unavailable' && !sso && (
                  <HelperText className="pf-v6-u-mb-md">
                    <HelperTextItem>OpenShift sign-in is not available right now; connect with your MongoDB credentials.</HelperTextItem>
                  </HelperText>
                )}
              </>
            )}

            {showMongoForm && !ssoRequiredButMissing && <MongoLoginForm me={me} from={from} blocked={!!mongo || reason === 'logout' || reason === 'signedout'} />}
          </CardBody>
        </Card>
      </main>
    </div>
  );
}

/** Starts an automatic MONGODB-OIDC connection after single sign-on. */
function AutoConnect({ profile, from, reconnect, onCancel }: { profile: Profile; from?: string; reconnect: boolean; onCancel: () => void }) {
  useEffect(() => {
    const t = window.setTimeout(() => {
      markAutoAttempt(profile.name);
      rememberProfile(profile.name);
      browser.assign(startURL(profile.oidc!.url, from, true));
    }, 700);
    return () => window.clearTimeout(t);
  }, [profile, from]);
  return (
    <div className="portal-autoconnect" role="status">
      <Spinner size="xl" aria-hidden />
      <div>
        <Title headingLevel="h3" size="lg">
          {reconnect ? 'Reconnecting' : 'Connecting'} to {profile.displayName}
        </Title>
        <Content component="p" className="portal-muted">
          Using your {profile.oidc!.displayName} identity with MongoDB OIDC. No password is needed.
        </Content>
        <Button variant="link" isInline onClick={onCancel}>
          Choose another way to connect
        </Button>
      </div>
    </div>
  );
}

function MongoLoginForm({ me, from, blocked }: { me: Me; from?: string; blocked: boolean }) {
  const profiles = useProfiles();
  const login = useLogin();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [selected, setSelected] = useState<string | undefined>(() => params.get('profile') || lastProfile());
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [capsLock, setCapsLock] = useState(false);
  const [authSourceEdit, setAuthSource] = useState<string>();
  const [mechanism, setMechanism] = useState('');
  const [advanced, setAdvanced] = useState(false);
  const [autoCancelled, setAutoCancelled] = useState(false);

  const profile: Profile | undefined = profiles.data?.find((p) => p.name === selected) ?? profiles.data?.[0];
  const authSource = authSourceEdit ?? profile?.defaultAuthSource ?? '';
  const passwordMechanisms = (profile?.authMechanisms ?? []).filter((m) => m !== 'MONGODB-OIDC');
  // Hide the password form only for a profile known to offer OIDC alone.
  const passwordLogin = !profile || passwordMechanisms.length > 0;
  const ret = safeFrom(from);

  // Automatic MONGODB-OIDC after single sign-on: the remembered profile if it
  // allows it, otherwise the first one that does.
  const autoProfile =
    me.sso && !blocked && !autoCancelled
      ? [profiles.data?.find((p) => p.name === lastProfile()), ...(profiles.data ?? [])].find((p) => p?.oidc?.autoConnect && !autoAttempted(p.name))
      : undefined;
  if (autoProfile) {
    return <AutoConnect profile={autoProfile} from={from} reconnect={params.get('reason') === 'required'} onCancel={() => setAutoCancelled(true)} />;
  }

  const select = (p: Profile) => {
    setSelected(p.name);
    setAuthSource(undefined);
    setMechanism('');
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!profile) return;
    try {
      await login.mutateAsync({ profile: profile.name, username, password, authSource, mechanism });
      setPassword('');
      rememberProfile(profile.name);
      navigate(ret, { replace: true });
    } catch {
      setPassword('');
    }
  };

  const err = login.error;
  const retryAfter = err instanceof ApiError && err.code === 'rate_limited';
  const capsHandler = (e: React.KeyboardEvent) => setCapsLock(e.getModifierState?.('CapsLock') ?? false);

  return (
    <>
      <Title headingLevel="h3" size="md" className="pf-v6-u-mb-sm">
        Connection profile
      </Title>
      {profiles.isPending && <Spinner size="lg" aria-label="Loading profiles" />}
      {profiles.isError && <ErrorState error={profiles.error} onRetry={() => void profiles.refetch()} />}
      <Gallery hasGutter minWidths={{ default: '220px' }} role="radiogroup" aria-label="Connection profiles">
        {profiles.data?.map((p) => (
          <Card key={p.name} isCompact isSelectable isSelected={profile?.name === p.name} id={`profile-${p.name}`} className="portal-profile-card">
            <CardHeader
              selectableActions={{
                selectableActionId: `profile-input-${p.name}`,
                selectableActionAriaLabelledby: `profile-${p.name}`,
                name: 'profile',
                variant: 'single',
                onChange: () => select(p),
                isChecked: profile?.name === p.name,
              }}
            >
              <CardTitle>{p.displayName}</CardTitle>
            </CardHeader>
            <CardBody>
              {p.description && <Content component="small">{p.description}</Content>}
              <LabelGroup className="pf-v6-u-mt-sm" numLabels={4}>
                <HealthLabel h={p.health} />
                {p.tlsMode === 'enabled' ? (
                  <Label color="green" icon={<LockIcon />} isCompact>
                    TLS{p.clientCertificate ? ' + client cert' : ''}
                  </Label>
                ) : (
                  <Label color="red" icon={<UnlockIcon />} isCompact>
                    Unencrypted
                  </Label>
                )}
                {p.oidc && (
                  <Label color="purple" icon={<KeyIcon />} isCompact>
                    OIDC
                  </Label>
                )}
                {p.replicaSet && <Label isCompact>rs: {p.replicaSet}</Label>}
              </LabelGroup>
            </CardBody>
          </Card>
        ))}
      </Gallery>

      {profile && (profile.health?.state === 'offline' || profile.health?.state === 'misconfigured') && (
        <Alert className="pf-v6-u-mt-md" variant="warning" isInline isPlain title="This MongoDB deployment is not reachable right now">
          <p>{profile.health.reason}</p>
          {me.authenticated && <DiagnosticsPanel profile={profile.name} compact />}
        </Alert>
      )}
      {profile?.plaintextWarning && (
        <Alert className="pf-v6-u-mt-md" variant="warning" isInline title="This connection is not encrypted">
          MongoDB TLS is disabled for this profile. Your username, password and all data travel between the portal and MongoDB without
          transport encryption. Use this profile only where an approved security exception exists.
        </Alert>
      )}

      {profile?.oidc && (
        <div className="pf-v6-u-mt-lg">
          <Button
            variant="primary"
            size="lg"
            isBlock
            icon={<KeyIcon />}
            component="a"
            href={`${profile.oidc.url}?return=${encodeURIComponent(ret)}`}
            onClick={() => rememberProfile(profile.name)}
          >
            Connect with {profile.oidc.displayName}
          </Button>
          <Content component="small" className="pf-v6-u-display-block pf-v6-u-mt-xs portal-muted">
            MongoDB OIDC: MongoDB receives your own token from the identity provider it trusts. No password.
          </Content>
          {passwordLogin && <Divider className="pf-v6-u-my-md" />}
        </div>
      )}
      {passwordLogin && (
        <Form className="pf-v6-u-mt-lg" onSubmit={(e) => void submit(e)} aria-label="MongoDB login">
          <Content component="small" className="portal-callout">
            {me.sso ? (
              <>
                <strong>Database sign-in is separate from portal sign-in.</strong> You are signed in to the portal as {me.user}; MongoDB checks the
                database credentials below and decides what you can do.
              </>
            ) : (
              <>Without single sign-on your MongoDB user is your portal identity; the portal RBAC policy applies to it.</>
            )}
          </Content>
          <FormGroup label="MongoDB username" isRequired fieldId="username">
            <TextInput id="username" value={username} onChange={(_e, v) => setUsername(v)} isRequired autoComplete="username" autoFocus={!profile?.oidc} />
          </FormGroup>
          <FormGroup label="Password" isRequired fieldId="password">
            <InputGroup>
              <InputGroupItem isFill>
                <TextInput
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(_e, v) => setPassword(v)}
                  onKeyUp={capsHandler}
                  onKeyDown={capsHandler}
                  isRequired
                  autoComplete="current-password"
                />
              </InputGroupItem>
              <InputGroupItem>
                <Button
                  variant="control"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  onClick={() => setShowPassword((v) => !v)}
                  icon={showPassword ? <EyeSlashIcon /> : <EyeIcon />}
                />
              </InputGroupItem>
            </InputGroup>
            {capsLock && (
              <FormHelperText>
                <HelperText>
                  <HelperTextItem variant="warning">Caps Lock is on</HelperTextItem>
                </HelperText>
              </FormHelperText>
            )}
          </FormGroup>
          <ExpandableSection toggleText={advanced ? 'Hide advanced options' : 'Advanced options'} onToggle={(_e, v) => setAdvanced(v)} isExpanded={advanced}>
            <FormGroup label="Authentication database" isRequired fieldId="authSource">
              <TextInput id="authSource" value={authSource} onChange={(_e, v) => setAuthSource(v)} isRequired />
            </FormGroup>
            <FormGroup label="Authentication mechanism" fieldId="mechanism" className="pf-v6-u-mt-md">
              <FormSelect id="mechanism" value={mechanism} onChange={(_e, v) => setMechanism(v)}>
                <FormSelectOption value="" label="Negotiate (recommended)" />
                {passwordMechanisms.map((m) => (
                  <FormSelectOption key={m} value={m} label={m} />
                ))}
              </FormSelect>
            </FormGroup>
          </ExpandableSection>
          <Content component="small" className="portal-muted">
            Your password is sent once to MongoDB for verification and is never stored by the portal.
          </Content>
          {err && (
            <Alert variant={retryAfter ? 'warning' : 'danger'} isInline title={errorMessage(err)}>
              {err instanceof ApiError && err.code === 'tls_verification_failed' &&
                'The MongoDB server certificate could not be verified against the configured CA. Contact the platform team.'}
              {err instanceof ApiError && err.code === 'mongo_unavailable' && 'MongoDB did not respond. It may be down or unreachable from the portal.'}
              {err instanceof ApiError && ['tls_verification_failed', 'mongo_unavailable'].includes(err.code) && me.authenticated && profile && (
                <div className="pf-v6-u-mt-sm">
                  <DiagnosticsPanel profile={profile.name} compact />
                </div>
              )}
            </Alert>
          )}
          <ActionGroup>
            <Button type="submit" variant={profile?.oidc ? 'secondary' : 'primary'} isDisabled={!profile || !username || !password || login.isPending} isLoading={login.isPending}>
              Connect with password
            </Button>
          </ActionGroup>
        </Form>
      )}
    </>
  );
}
