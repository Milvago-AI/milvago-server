import { useState } from 'react';
import { Card, ErrorNotice, Notice, ResourceView, useMutation, useResource, useText } from './ui';

/** Who may register a connector by itself, as the identity provider enforces it.
 *
 * There is no copy of this in Milvago's own database: the screen reads and writes the realm, so
 * what it shows is what is actually enforced. A deployment starts closed, and opening it always
 * names the hosts a sign-in may be returned to — the field is what bounds the whole thing. */
export type McpRegistration = {
  enabled: boolean;
  unbounded: boolean;
  hosts: string[];
  max_clients: number;
  scopes: string[];
  client_id: string;
};

export function ConnectorRegistrationPanel() {
  const t = useText();
  const resource = useResource<McpRegistration>('/api/mcp/registration');
  return (
    <Card
      className="settings-panel"
      title={t('connectorSelfRegistration')}
      description={t('aConnectorAsksTheIdentityProvider')}
      flush
    >
      <ResourceView resource={resource}>
        {data => <RegistrationForm initial={data} />}
      </ResourceView>
    </Card>
  );
}

function RegistrationForm({ initial }: Readonly<{ initial: McpRegistration }>) {
  const t = useText();
  const mutation = useMutation();
  const [state, setState] = useState(initial);
  const [hosts, setHosts] = useState(initial.hosts.join('\n'));
  const [saved, setSaved] = useState(false);
  async function save() {
    setSaved(false);
    try {
      const updated = await mutation.run<McpRegistration>('/api/mcp/registration', 'PUT', {
        enabled: state.enabled,
        hosts: hosts.split('\n').map(line => line.trim()).filter(Boolean),
        max_clients: state.max_clients,
      });
      if (updated) {
        setState(updated);
        setHosts(updated.hosts.join('\n'));
      }
      setSaved(true);
    } catch { /* Displayed by ErrorNotice. */ }
  }
  return (
    <div style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 14 }}>
      <ErrorNotice error={mutation.error} />
      {/* A realm with no host policy at all: every client on the internet may register. This
          screen cannot produce that state, so it says what it is instead of calling it "on". */}
      {state.unbounded && (
        <Notice tone="warning" title={t('registrationIsOpenToEveryHost')}>
          {t('thisInstanceAcceptsARegistrationFrom')}
        </Notice>
      )}
      <div className="field">
        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={state.enabled}
            onChange={e => setState({ ...state, enabled: e.target.checked })}
          />
          <span>{t('letAConnectorRegisterItself')}</span>
        </label>
      </div>
      <div className="field">
        <span className="label">{t('hostsAllowedToReceiveASignIn')}</span>
        <textarea
          rows={4}
          className="mono"
          value={hosts}
          disabled={!state.enabled}
          onChange={e => setHosts(e.target.value)}
          placeholder={'claude.ai\nclaude.com'}
        />
        <span className="help">{t('oneHostPerLineNoSchemeNoPath')}</span>
      </div>
      <div className="field">
        <span className="label">{t('registeredClientCeiling')}</span>
        <input
          type="number"
          min={1}
          max={1000}
          value={state.max_clients}
          onChange={e => setState({ ...state, max_clients: Number(e.target.value) })}
        />
        <span className="help">{t('aRegistrationThatWouldExceedThis')}</span>
      </div>
      <Notice tone="neutral" title={t('whatIsGuaranteedWhateverYouAllow')}>
        {t('consentIsAlwaysAskedAndA', [state.scopes.join(', '), state.client_id])}
      </Notice>
      <div className="actions">
        <button className="button primary" disabled={mutation.pending} onClick={() => void save()}>
          {t('save')}
        </button>
        {saved && <span className="help">{t('settingsSaved')}</span>}
      </div>
    </div>
  );
}
