import { useState } from 'react';
import { useNavigate } from 'react-router';
import { Alert, Button, Checkbox, Content, Modal, ModalBody, ModalHeader, ModalVariant } from '@patternfly/react-core';
import { BroomIcon, DatabaseIcon, PlugIcon, SyncAltIcon, UserCheckIcon } from '@patternfly/react-icons';
import { useQueryClient } from '@tanstack/react-query';
import { keys, useLogout } from '../api/hooks';
import type { SessionInfo } from '../api/types';
import { browser } from '../lib/nav';
import { clearPersonalData } from '../lib/recent';

/** Personal refresh and reconnect controls. They act on this browser and
 * this user's MongoDB connection only; shared portal caches are managed by
 * administrators on the Caches page. */
export function ConnectionPanel({ isOpen, onClose, session }: { isOpen: boolean; onClose: () => void; session?: SessionInfo }) {
  const qc = useQueryClient();
  const logout = useLogout();
  const navigate = useNavigate();
  const [snippets, setSnippets] = useState(false);
  const [done, setDone] = useState('');

  const refresh = async (what: string, keyList?: readonly (readonly string[])[]) => {
    if (keyList) await Promise.all(keyList.map((k) => qc.invalidateQueries({ queryKey: k })));
    else await qc.invalidateQueries();
    setDone(what);
  };

  const reconnect = async () => {
    const profile = session?.profile;
    const oidc = session?.profileInfo?.oidc;
    try {
      localStorage.removeItem('mongo-portal-autoconnect');
    } catch {
      // ignore
    }
    try {
      await logout.mutateAsync();
    } catch {
      // the session may already be gone
    }
    onClose();
    if (oidc) {
      browser.assign(`${oidc.url}?return=${encodeURIComponent(window.location.pathname + window.location.search)}&silent=1`);
      return;
    }
    navigate(`/login?reason=reconnect${profile ? `&profile=${encodeURIComponent(profile)}` : ''}`, { replace: true });
  };

  return (
    <Modal variant={ModalVariant.medium} isOpen={isOpen} onClose={onClose} aria-labelledby="conn-title">
      <ModalHeader title="Refresh & connection" labelId="conn-title" description="These actions affect only you and this browser." />
      <ModalBody>
        {done && <Alert className="pf-v6-u-mb-md" isInline isPlain variant="success" title={done} />}
        <div className="portal-action-list">
          <div className="portal-action">
            <SyncAltIcon />
            <div>
              <strong>Refresh portal data</strong>
              <Content component="small">Reload everything shown in the portal from the server.</Content>
            </div>
            <Button variant="secondary" onClick={() => void refresh('Portal data refreshed.')}>
              Refresh
            </Button>
          </div>
          <div className="portal-action">
            <DatabaseIcon />
            <div>
              <strong>Refresh database list</strong>
              <Content component="small">Discover databases and collections again (for example after one was created elsewhere).</Content>
            </div>
            <Button variant="secondary" onClick={() => void refresh('Databases and collections refreshed.', [keys.databases, ['collections']])}>
              Refresh
            </Button>
          </div>
          <div className="portal-action">
            <UserCheckIcon />
            <div>
              <strong>Refresh connection status</strong>
              <Content component="small">Check your sign-in, MongoDB session and the deployment health again.</Content>
            </div>
            <Button variant="secondary" onClick={() => void refresh('Connection status refreshed.', [keys.me, keys.session, keys.status, keys.profiles])}>
              Refresh
            </Button>
          </div>
          <div className="portal-action">
            <PlugIcon />
            <div>
              <strong>Reconnect to MongoDB</strong>
              <Content component="small">
                {session?.profileInfo?.oidc
                  ? `Opens a new MongoDB connection with your ${session.profileInfo.oidc.displayName} identity.`
                  : 'Ends this MongoDB session and asks for your database credentials again.'}
              </Content>
            </div>
            <Button variant="secondary" onClick={() => void reconnect()} isLoading={logout.isPending} isDisabled={!session}>
              Reconnect
            </Button>
          </div>
          <div className="portal-action">
            <BroomIcon />
            <div>
              <strong>Clear personal UI data</strong>
              <Content component="small">Forget recent databases and the last profile in this browser. The theme is kept.</Content>
              <Checkbox id="clear-snippets" className="pf-v6-u-mt-xs" label="Also delete my saved shell snippets" isChecked={snippets} onChange={(_e, v) => setSnippets(v)} />
            </div>
            <Button
              variant="secondary"
              onClick={() => {
                clearPersonalData({ snippets });
                setDone(snippets ? 'Personal UI data and saved snippets cleared.' : 'Personal UI data cleared.');
              }}
            >
              Clear
            </Button>
          </div>
        </div>
      </ModalBody>
    </Modal>
  );
}
