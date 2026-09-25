import { Fragment, useContext, useState } from "react";
import type { SubmitEvent } from "react";
import { ApiError } from "./api";
import type { ApiKey, ApiKeyCreated, ApiKeyExpiryDays } from "./api";
import { permLabel } from "./RolesPanel";
import {
  Badge,
  Card,
  Context,
  DateValue,
  Dialog,
  Empty,
  ErrorNotice,
  Icon,
  Notice,
  ResourceView,
  copyToClipboard,
  useMutation,
  useResource,
  useText,
} from "./ui";

// `demo_mcp_key` n'arrive que d'une instance de démonstration en lecture seule, qui
// publie sa clé MCP : elle ne peut pas en créer une, donc sans cela l'endpoint qu'elle
// annonce reste inutilisable.
type ApiKeysResponse = { items: ApiKey[]; content_access_available: boolean; demo_mcp_key?: string };

const expiryChoices: ApiKeyExpiryDays[] = [30, 90, 365];
const activeLimit = 5;
// Kept in step with mcp_commercial.go: the product's own revision, which removed
// the initialize handshake, and the published one every client in the field opens
// with. Both are shown so someone configuring a client can tell at a glance that
// theirs is served.
const mcpProtocolVersion = "2026-07-28";
const mcpPublishedVersion = "2025-06-18";
// Kept in step with mcpClientID in the server's mcp_identity_commercial.go. Public
// by design -- it is a name, not a secret -- and only needed by a client that asks
// for one.
const mcpClientId = "milvago-mcp-client";

const codeBox = {
  padding: "10px 12px",
  background: "var(--surface-2)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius-s)",
  overflowWrap: "anywhere" as const,
};

/**
 * Personal API credentials, on the profile page.
 *
 * The create dialog is a **sibling** of the ResourceView, not one of its
 * children, and that placement is load-bearing rather than stylistic: on success
 * the dialog reloads the list while still displaying the secret, and `reload()`
 * sets the resource data to `undefined`, which unmounts everything the
 * ResourceView renders. As a child, the dialog would be torn down mid-reveal and
 * the one and only copy of the secret would vanish before the user could take it.
 * Same shape as MembersPanel/InvitationDialog.
 */
export function ApiKeysPanel() {
  const t = useText();
  const { session } = useContext(Context);
  const resource = useResource<ApiKeysResponse>("/api/profile/api-keys");
  // Held above the ResourceView for the same reason: a reload would drop it.
  const [saved, setSaved] = useState("");
  const [creating, setCreating] = useState(false);
  const atLimit = (resource.data?.items.length ?? 0) >= activeLimit;
  return (
    <>
    <section className="panel table-panel">
      <div className="section-heading">
        <div>
          <h2>{t("apiKeys")}</h2>
          <p>
            {t("soAScriptOrAnExternal")}
          </p>
        </div>
        <button
          className="button primary"
          disabled={atLimit}
          title={
            atLimit
              ? t("limitOf5ActiveKeysReached")
              : undefined
          }
          onClick={() => {
            setSaved("");
            setCreating(true);
          }}
        >
          <Icon name="plus" />
          {t("newApiKey")}
        </button>
      </div>
      {saved && (
        <output className="notice success">
          <Icon name="check" />
          {saved}
        </output>
      )}
      <ResourceView resource={resource}>
        {(data) => (
          <ApiKeysTable
            items={data.items}
            reload={resource.reload}
            onRevoked={() => setSaved(t("keyRevoked"))}
          />
        )}
      </ResourceView>
      {creating && (
        <CreateApiKeyDialog
          contentAvailable={resource.data?.content_access_available ?? false}
          close={() => setCreating(false)}
          onCreated={resource.reload}
        />
      )}
    </section>
    {/*
      The MCP endpoint is an Enterprise module, so the card follows the runtime
      edition rather than a build flag, like every other Enterprise surface in
      this console. It sits here because the credential it needs is one of the
      keys above: there is no separate MCP sign-in to present.
    */}
    {session.edition === "commercial" && <McpEndpointCard demoKey={resource.data?.demo_mcp_key ?? ""} />}
    </>
  );
}

type CopyState = "idle" | "done" | "failed";

function McpEndpointCard({ demoKey }: Readonly<{ demoKey: string }>) {
  const t = useText();
  const [copied, setCopied] = useState<CopyState>("idle");
  const [copiedKey, setCopiedKey] = useState<CopyState>("idle");
  const endpoint = `${window.location.origin}/mcp`;
  return (
    <Card
      title={t("mcpServer")}
      description={t("toConnectALanguageModelTo")}
    >
      <div className="field">
        <span className="label">{t("endpoint")}</span>
        <div style={codeBox}>
          <code className="mono">{endpoint}</code>
        </div>
        <span className="help">
          {t("declareItInYourClientAs")}
        </span>
      </div>
      <div className="field">
        <span className="label">{t("signInWithYourAccount")}</span>
        <div style={codeBox}>
          <code className="mono">{mcpClientId}</code>
        </div>
        <span className="help">
          {t("mostClientsOnlyNeedTheEndpoint")}
        </span>
      </div>
      <div className="field">
        <span className="label">{t("authenticationHeader")}</span>
        <div style={codeBox}>
          <code className="mono">Authorization: Bearer {demoKey || "mvk_…"}</code>
        </div>
        <span className="help">
          {t("requiredOnEveryMethodDiscoveryIncluded")}
        </span>
      </div>
      {/* La clé publiée d'une démonstration : elle s'affiche parce qu'elle est faite
          pour être distribuée, et parce que l'instance ne peut pas en créer une. */}
      {demoKey && (
        <div className="field">
          <span className="label">{t("demoPublishedKey")}</span>
          <div style={codeBox}>
            <code className="mono">{demoKey}</code>
          </div>
          <span className="help">{t("demoPublishedKeyHelp")}</span>
          <div className="actions">
            <button
              className="button secondary"
              onClick={async () => setCopiedKey((await copyToClipboard(demoKey)) ? "done" : "failed")}
            >
              <Icon name={copiedKey === "done" ? "check" : "copy"} />
              {copiedKey === "done" ? t("copied") : t("copyTheKey")}
            </button>
          </div>
          {copiedKey === "failed" && <Notice tone="warning">{t("automaticCopyFailedSelectTheUrl")}</Notice>}
        </div>
      )}
      <div className="actions">
        <button
          className="button secondary"
          onClick={async () => setCopied((await copyToClipboard(endpoint)) ? "done" : "failed")}
        >
          <Icon name={copied === "done" ? "check" : "copy"} />
          {copied === "done" ? t("copied") : t("copyUrl")}
        </button>
      </div>
      {copied === "failed" && (
        <Notice tone="warning">
          {t("automaticCopyFailedSelectTheUrl")}
        </Notice>
      )}
      <Notice tone="neutral" title={t("protocolRevision")}>
        {t("twoRevisionsAreServed0And1", [mcpProtocolVersion, mcpPublishedVersion])}
      </Notice>
      <Notice tone="warning" title={t("readOnlyAndUntrustedData")}>
        {t("noToolChangesAPolicyA")}
      </Notice>
    </Card>
  );
}

function PermissionsCell({ permissions }: Readonly<{ permissions: string[] }>) {
  const t = useText();
  const labels = permissions.map((p) => permLabel(t, p));
  if (labels.length === 0) return <span className="muted">—</span>;
  // Up to two read as prose; beyond that a full list overflows the row, so the
  // count carries the summary and the native tooltip carries the detail.
  if (labels.length <= 2) return <>{labels.join(", ")}</>;
  return (
    <span title={labels.join(", ")}>
      <Badge>
        {labels.length} {t("permissions")}
      </Badge>
    </span>
  );
}

function ExpiryCell({ value }: Readonly<{ value: string }>) {
  const t = useText();
  const at = Date.parse(value);
  if (Number.isNaN(at)) return <span className="muted">—</span>;
  if (at <= Date.now())
    return (
      <span title={value}>
        <Badge tone="danger">{t("expired")}</Badge>
      </span>
    );
  const days = Math.max(1, Math.ceil((at - Date.now()) / 86400000));
  return (
    <span title={value}>
      {days > 1
        ? t("expiresIn0Days", [days])
        : t("expiresTomorrow")}
    </span>
  );
}

function ApiKeysTable({
  items,
  reload,
  onRevoked,
}: Readonly<{
  items: ApiKey[];
  reload: () => void;
  onRevoked: () => void;
}>) {
  const t = useText();
  const mutation = useMutation();
  // Row-scoped, so it is safe inside the ResourceView: the row it belongs to
  // disappears on reload anyway.
  const [confirming, setConfirming] = useState<string>();
  if (items.length === 0)
    return (
      <Empty title={t("noApiKeys")}>
        {t("createAKeySoAnExternal")}
      </Empty>
    );
  async function revoke(key: ApiKey) {
    try {
      await mutation.run(`/api/profile/api-keys/${encodeURIComponent(key.id)}`, "DELETE");
      setConfirming(undefined);
      onRevoked();
      reload();
    } catch {
      /* rendered by the ErrorNotice above the table */
    }
  }
  return (
    <>
      <ErrorNotice error={mutation.error} />
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>{t("name")}</th>
              <th>{t("permissions2")}</th>
              <th>{t("created")}</th>
              <th>{t("expires")}</th>
              <th>{t("lastUsed")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {items.map((key) => (
              <Fragment key={key.id}>
                <tr>
                  {/*
                    nowrap because a key name is a human phrase, not an
                    identifier. The other tables in the console hold hyphenated
                    machine names, which break cleanly at 390px; a phrase breaks
                    mid-word instead ("Auto maçã o do parqu e de máqui nas" in
                    Portuguese), and the longer languages make it worse. The
                    surrounding .table-scroll already absorbs the extra width, so
                    the reader scrolls a legible name rather than parsing a
                    shredded one.
                  */}
                  <td className="nowrap">
                    <strong>{key.name}</strong>
                    {key.content_access && (
                      <>
                        {" "}
                        <Badge tone="warning">{t("content")}</Badge>
                      </>
                    )}
                  </td>
                  <td>
                    <PermissionsCell permissions={key.permissions} />
                  </td>
                  <td>
                    <DateValue value={key.created_at} />
                  </td>
                  <td>
                    <ExpiryCell value={key.expires_at} />
                  </td>
                  <td>
                    {key.last_used_at ? (
                      <DateValue value={key.last_used_at} />
                    ) : (
                      <span className="muted">{t("neverUsed")}</span>
                    )}
                  </td>
                  <td>
                    <div className="row-actions">
                      <button
                        className="button danger small"
                        disabled={mutation.pending}
                        onClick={() => setConfirming(key.id)}
                      >
                        <Icon name="trash" />
                        {t("revoke")}
                      </button>
                    </div>
                  </td>
                </tr>
                {confirming === key.id && (
                  <tr>
                    <td colSpan={6}>
                      <Notice
                        tone="warning"
                        title={t("revokeThisKey")}
                        action={
                          <>
                            <button
                              className="button secondary small"
                              onClick={() => setConfirming(undefined)}
                            >
                              {t("cancel")}
                            </button>
                            <button
                              className="button danger small"
                              disabled={mutation.pending}
                              onClick={() => revoke(key)}
                            >
                              {t("confirmRevocation")}
                            </button>
                          </>
                        }
                      >
                        {t("anyToolUsing0WillImmediately", [key.name])}
                      </Notice>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function CreateApiKeyDialog({
  contentAvailable,
  close,
  onCreated,
}: Readonly<{
  contentAvailable: boolean;
  close: () => void;
  onCreated: () => void;
}>) {
  const t = useText();
  const { session } = useContext(Context);
  const mutation = useMutation();
  const [name, setName] = useState("");
  const [days, setDays] = useState<ApiKeyExpiryDays>(30);
  const [permissions, setPermissions] = useState<string[]>([]);
  const [content, setContent] = useState(false);
  const [created, setCreated] = useState<ApiKeyCreated>();
  const [limitReached, setLimitReached] = useState(false);
  const [copied, setCopied] = useState<"idle" | "done" | "failed">("idle");
  // Nothing is pre-checked: a key should start with no authority and be widened
  // deliberately, and the list is the caller's own rights so it can never offer
  // a permission the server would refuse.
  const offered = session.permissions ?? [];

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    try {
      const result = await mutation.run<ApiKeyCreated>("/api/profile/api-keys", "POST", {
        name: name.trim(),
        expires_in_days: days,
        permissions,
        content_access: content,
      });
      if (result) {
        setCreated(result);
        onCreated();
      }
    } catch (error) {
      if (error instanceof ApiError && error.code === "api_key_limit") {
        mutation.clear();
        setLimitReached(true);
      }
      /* anything else stays visible through the ErrorNotice below */
    }
  }

  if (created)
    return (
      <Dialog title={t("yourNewApiKey")} close={close}>
        <p>
          {t("copyThisKeyNowItWill")}
        </p>
        <div className="field">
          <span className="label">{t("secretKey")}</span>
          <div
            style={{
              padding: "10px 12px",
              background: "var(--surface-2)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-s)",
            }}
          >
            <code className="mono">{created.secret}</code>
          </div>
        </div>
        <div className="actions">
          <button
            className="button secondary"
            onClick={async () => setCopied((await copyToClipboard(created.secret)) ? "done" : "failed")}
          >
            <Icon name={copied === "done" ? "check" : "copy"} />
            {copied === "done" ? t("copied") : t("copyKey")}
          </button>
        </div>
        {copied === "failed" && (
          <Notice tone="warning">
            {t("automaticCopyFailedSelectTheText")}
          </Notice>
        )}
        <Notice
          tone="warning"
          title={t("youWillNotBeAbleTo")}
        >
          {t("ifYouLoseItRevokeThis")}
        </Notice>
        <div className="dialog-actions">
          <button className="button primary" onClick={close}>
            {t("done")}
          </button>
        </div>
      </Dialog>
    );

  return (
    <Dialog
      title={t("newApiKey")}
      close={() => {
        if (!mutation.pending) close();
      }}
    >
      <form onSubmit={submit}>
        <fieldset disabled={mutation.pending} style={{ border: "none", padding: 0, margin: 0 }}>
          <div className="field">
            <label>
              <span className="label">{t("keyName")}</span>
              <input
                required
                maxLength={60}
                autoFocus
                value={name}
                placeholder={t("eGSiemExport")}
                onChange={(event) => setName(event.target.value)}
              />
            </label>
          </div>
          <div className="field">
            <span className="label">{t("validity")}</span>
            {expiryChoices.map((choice) => (
              <label key={choice} className="checkbox-label">
                <input
                  type="radio"
                  name="api-key-expiry"
                  checked={days === choice}
                  onChange={() => setDays(choice)}
                />
                <span>{t("n0Days", [choice])}</span>
              </label>
            ))}
          </div>
          <div className="field">
            <span className="label">{t("permissions2")}</span>
            {offered.map((permission) => (
              <label key={permission} className="checkbox-label">
                <input
                  type="checkbox"
                  checked={permissions.includes(permission)}
                  onChange={(event) =>
                    setPermissions((current) =>
                      event.target.checked
                        ? [...current, permission]
                        : current.filter((p) => p !== permission),
                    )
                  }
                />
                <span>{permLabel(t, permission)}</span>
              </label>
            ))}
            <span className="help">
              {t("limitedToYourOwnRightsAnd")}
            </span>
          </div>
          {/*
            The one permission whose reach outlives the key. An installer carries
            the organization's deployment key, which does not expire, so anyone
            who downloaded one keeps the ability to enrol devices after this key
            is gone. Accepted deliberately rather than blocked (a key is the
            natural way to automate a mass deployment) — so it has to be said at
            the moment the box is ticked, not buried in documentation.
          */}
          {permissions.includes("installers.manage") && (
            <Notice
              tone="warning"
              title={t("thisPermissionOutlivesTheKey")}
            >
              {t("aKeyThatCanDownloadThe")}
            </Notice>
          )}
          {contentAvailable && (
            <div className="field">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={content}
                  onChange={(event) => setContent(event.target.checked)}
                />
                <span>
                  {t("allowReadingPromptContent")}
                </span>
              </label>
              <span className="help">
                {t("enableOnlyIfTheToolNeeds")}
              </span>
            </div>
          )}
          {/*
            Same discipline as the installers.manage warning above: the box is
            where the decision is taken, so this is where its reach has to be
            said. In Enterprise a key can also be presented to the MCP endpoint,
            which answers a language model — so ticking this box is what lets the
            text of a user's prompt leave for a model provider.
          */}
          {contentAvailable && content && session.edition === "commercial" && (
            <Notice
              tone="warning"
              title={t("promptTextWillBeAbleTo")}
            >
              {t("thisKeyAlsoOpensTheMcp")}
            </Notice>
          )}
        </fieldset>
        {limitReached && (
          <Notice tone="warning" title={t("keyLimitReached")}>
            {t("youAlreadyHave5ActiveKeys")}
          </Notice>
        )}
        <ErrorNotice error={mutation.error} />
        <div className="dialog-actions">
          <button
            type="button"
            className="button secondary"
            disabled={mutation.pending}
            onClick={close}
          >
            {t("cancel")}
          </button>
          <button
            type="submit"
            className="button primary"
            disabled={mutation.pending || !name.trim() || permissions.length === 0}
          >
            {mutation.pending ? t("creating") : t("createKey")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
