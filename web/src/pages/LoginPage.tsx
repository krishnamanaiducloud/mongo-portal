import { useState } from 'react';
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
import { HealthLabel, IdentityLabel, sourceDescription } from '../components/Indicators';
import { RolesLabel } from '../components/Permission';
import { lastProfile, rememberProfile } from '../lib/recent';
import { ErrorState } from './StatusPages';

const reasons: Record<string, string> = {
  expired: 'Your MongoDB session expired. Sign in again to continue.',
  required: 'Sign in to continue. Sessions do not survive portal restarts or moves between portal instances.',
  logout: 'You have been disconnected from MongoDB.',
  signedout: 'You have signed out of the portal.',
};

const ssoMessages: Record<string, { title: string; body: string }> = {
  unavailable: {
    title: 'OpenShift sign-in is not available right now',
    body: 'The OpenShift OAuth server could not be reached from the portal. You can still connect with your MongoDB credentials.',
  },
  failed: { title: 'OpenShift sign-in did not complete', body: 'Try again, or connect with your MongoDB credentials.' },
  denied: { title: 'OpenShift sign-in was cancelled', body: 'Access was not granted at the OpenShift login page.' },
  expired: { title: 'The OpenShift sign-in took too long', body: 'Start the sign-in again.' },
};

function startURL(base: string, from: string | undefined) {
  const ret = from && from.startsWith('/') && !from.startsWith('//') && from !== '/login' ? from : '/';
  return `${base}?return=${encodeURIComponent(ret)}`;
}

export function LoginPage({ me }: { me: Me }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [params] = useSearchParams();
  const signOut = useSignOut();
  const from = (location.state as { from?: string } | null)?.from;
  const auth = me.auth;
  const osAvailable = auth.openshift.state === 'available';
  const ssoRequiredButMissing = auth.requireSSO && !me.sso;
  // MongoDB credentials are asked for after SSO, or directly when SSO is not used.
  const [mongoOnly, setMongoOnly] = useState(false);
  const showMongoForm = me.sso || (auth.mongodbLogin && (!osAvailable || mongoOnly));

  if (me.hasSession && !params.get('reason')) {
    return <Navigate to={from && from !== '/login' ? from : '/'} replace />;
  }

  const reason = params.get('reason');
  const sso = params.get('sso');
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
          <Title headingLevel="h1" size="3xl" className="portal-login-title">
            <DatabaseIcon /> MongoDB Portal
          </Title>
          {me.environment && (
            <Label color="grey" className="pf-v6-u-mb-md">
              {me.environment}
            </Label>
          )}
          <Content component="p" className="portal-login-tagline">
            Browse, query and administer MongoDB with your own identity.
          </Content>
          <ul className="portal-login-points">
            <li>
              <KeyIcon /> Your own MongoDB credentials — never stored by the portal
            </li>
            <li>
              <UserShieldIcon /> Role-based access from your OpenShift groups
            </li>
            <li>
              <ShieldAltIcon /> Every change is audited
            </li>
          </ul>
          <div className="portal-login-version">
            {me.build.version} · {me.build.commit.slice(0, 7)}
          </div>
        </div>
      </section>

      <main className="portal-login-main">
        <Card className="portal-login-card" isLarge>
          <CardHeader>
            <CardTitle>
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
                  <Button
                    variant="primary"
                    size="lg"
                    isBlock
                    icon={<OpenshiftIcon />}
                    component="a"
                    href={startURL(auth.openshiftURL, from)}
                    className="portal-sso-button"
                  >
                    Log in with OpenShift
                  </Button>
                )}
                {ssoRequiredButMissing && !osAvailable && (
                  <Alert variant="info" isInline title="Single sign-on is required">
                    This portal accepts only single sign-on, which is not available right now
                    {auth.openshift.reason ? ` (${auth.openshift.reason})` : ''}. It is checked again automatically; reload the page in a
                    moment.
                  </Alert>
                )}
                {osAvailable && auth.mongodbLogin && !mongoOnly && (
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

            {showMongoForm && !ssoRequiredButMissing && <MongoLoginForm me={me} from={from} />}
          </CardBody>
        </Card>
      </main>
    </div>
  );
}

function MongoLoginForm({ me, from }: { me: Me; from?: string }) {
  const profiles = useProfiles();
  const login = useLogin();
  const navigate = useNavigate();
  const [selected, setSelected] = useState<string | undefined>(() => lastProfile());
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [capsLock, setCapsLock] = useState(false);
  const [authSourceEdit, setAuthSource] = useState<string>();
  const [mechanism, setMechanism] = useState('');
  const [advanced, setAdvanced] = useState(false);

  const profile: Profile | undefined = profiles.data?.find((p) => p.name === selected) ?? profiles.data?.[0];
  const authSource = authSourceEdit ?? profile?.defaultAuthSource ?? '';

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
      navigate(from && from !== '/login' ? from : '/', { replace: true });
    } catch {
      setPassword('');
    }
  };

  const err = login.error;
  const retryAfter = err instanceof ApiError && err.code === 'rate_limited';
  const capsHandler = (e: React.KeyboardEvent) => setCapsLock(e.getModifierState?.('CapsLock') ?? false);

  return (
    <>
      {!me.sso && (
        <Content component="small" className="pf-v6-u-display-block pf-v6-u-mb-md">
          Without single sign-on your MongoDB user is your portal identity; the portal RBAC policy applies to it.
        </Content>
      )}
      <Title headingLevel="h3" size="md" className="pf-v6-u-mb-sm">
        Connection profile
      </Title>
      {profiles.isPending && <Spinner size="lg" aria-label="Loading profiles" />}
      {profiles.isError && <ErrorState error={profiles.error} onRetry={() => void profiles.refetch()} />}
      <Gallery hasGutter minWidths={{ default: '220px' }} role="radiogroup" aria-label="Connection profiles">
        {profiles.data?.map((p) => (
          <Card key={p.name} isCompact isSelectable isSelected={profile?.name === p.name} id={`profile-${p.name}`}>
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
                {p.replicaSet && <Label isCompact>rs: {p.replicaSet}</Label>}
              </LabelGroup>
            </CardBody>
          </Card>
        ))}
      </Gallery>

      {profile?.health?.state === 'offline' && (
        <Alert className="pf-v6-u-mt-md" variant="warning" isInline isPlain title="This MongoDB deployment is not reachable right now">
          {profile.health.reason}
        </Alert>
      )}
      {profile?.plaintextWarning && (
        <Alert className="pf-v6-u-mt-md" variant="warning" isInline title="This connection is not encrypted">
          MongoDB TLS is disabled for this profile. Your username, password and all data travel between the portal and MongoDB without
          transport encryption. Use this profile only where an approved security exception exists.
        </Alert>
      )}

      <Form className="pf-v6-u-mt-lg" onSubmit={(e) => void submit(e)} aria-label="MongoDB login">
        <FormGroup label="MongoDB username" isRequired fieldId="username">
          <TextInput id="username" value={username} onChange={(_e, v) => setUsername(v)} isRequired autoComplete="username" autoFocus />
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
              {profile?.authMechanisms.map((m) => <FormSelectOption key={m} value={m} label={m} />)}
            </FormSelect>
          </FormGroup>
        </ExpandableSection>
        <Content component="small">
          Your password is sent once to MongoDB for verification and is never stored by the portal.
        </Content>
        {err && (
          <Alert variant={retryAfter ? 'warning' : 'danger'} isInline title={errorMessage(err)}>
            {err instanceof ApiError && err.code === 'tls_verification_failed' &&
              'The MongoDB server certificate could not be verified against the configured CA. Contact the platform team.'}
            {err instanceof ApiError && err.code === 'mongo_unavailable' && 'MongoDB did not respond. It may be down or unreachable from the portal.'}
          </Alert>
        )}
        <ActionGroup>
          <Button type="submit" variant="primary" isDisabled={!profile || !username || !password || login.isPending} isLoading={login.isPending}>
            Connect
          </Button>
        </ActionGroup>
      </Form>
    </>
  );
}
