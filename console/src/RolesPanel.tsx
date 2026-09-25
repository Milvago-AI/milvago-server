import { useContext, useState } from "react";
import type { SubmitEvent } from "react";
import { ApiError } from "./api";
import type { Role, RoleMember, RoleMembersResponse } from "./api";
import type { TranslationKey } from "./locales/en";
import {
  useText,
  useResource,
  useMutation,
  ResourceView,
  ErrorNotice,
  Notice,
  Dialog,
  Icon,
  Context,
  can,
  canManage,
} from "./ui";
import type { Translate } from "./ui";

type RolesResponse = { items: Role[]; catalog: string[] };

const permissionLabels: Record<string, TranslationKey> = {
  "overview.read": "permOverviewRead",
  "events.read": "permEventsRead",
  "devices.read": "permDevicesRead",
  "devices.manage": "permDevicesManage",
  "members.read": "permMembersRead",
  "members.manage": "permMembersManage",
  "roles.manage": "permRolesManage",
  "observability.manage": "permObservabilityManage",
  "settings.manage": "permSettingsManage",
  "policy.manage": "permPolicyManage",
  "installers.manage": "permInstallersManage",
  "content.read": "permContentRead",
  "content.purge": "permContentPurge",
  "audit.read": "permAuditRead",
  "organizations.manage": "permOrganizationsManage",
  "directory.manage": "permDirectoryManage",
};

/** Shared with the API keys panel so the two never disagree on a wording. */
export function permLabel(t: Translate, key: string) {
  const label = permissionLabels[key];
  return label ? t(label) : key;
}

export function RolesPanel() {
  const resource = useResource<RolesResponse>("/api/roles");
  // The success message lives above the ResourceView: a reload clears the data,
  // which unmounts the children and would take any message held there with it.
  const [saved, setSaved] = useState("");
  return (
    <>
      {saved && (
        <output className="notice success">
          <Icon name="check" />
          {saved}
        </output>
      )}
      <ResourceView resource={resource}>
        {(data) => <RolesEditor data={data} reload={resource.reload} setSaved={setSaved} />}
      </ResourceView>
    </>
  );
}

function RolesEditor({
  data,
  reload,
  setSaved,
}: Readonly<{
  data: RolesResponse;
  reload: () => void;
  setSaved: (message: string) => void;
}>) {
  const t = useText();
  const { session } = useContext(Context);
  const manage = can(session, "roles.manage");
  const ownRole = session.organization.role;
  const [editing, setEditing] = useState<{ role?: Role } | null>(null);
  const [inUse, setInUse] = useState<Role | null>(null);
  const mutation = useMutation();

  async function remove(role: Role) {
    setSaved("");
    try {
      await mutation.run(`/api/roles/${encodeURIComponent(role.name)}`, "DELETE");
      setSaved(t("roleDeleted"));
      reload();
    } catch (error) {
      // A role still held by members cannot be deleted. Show who holds it so the
      // administrator can reassign or remove them without leaving the page.
      if (error instanceof ApiError && error.code === "role_in_use") {
        mutation.clear();
        setInUse(role);
      }
      /* Otherwise displayed via mutation.error below. */
    }
  }

  return (
    <div className="panel">
      <div className="section-heading">
        <h2>{t("rolesAndPermissions")}</h2>
        {manage && (
          <button className="button primary" onClick={() => { setSaved(""); mutation.clear(); setEditing({}); }}>
            <Icon name="plus" />
            {t("newRole")}
          </button>
        )}
      </div>
      <ErrorNotice error={mutation.error} />
      <table>
        <thead>
          <tr>
            <th>{t("role")}</th>
            <th>{t("permissions2")}</th>
            <th>{t("actions")}</th>
          </tr>
        </thead>
        <tbody>
          {data.items.map((role) => (
            <tr key={role.name}>
              <td>
                <span className="role-badge">{role.name}</span>
                {role.builtin && <span className="badge"> {t("builtIn")}</span>}
              </td>
              {/* A list of translated labels: it should wrap between them, never
                  inside one. Spanish and Portuguese labels are long enough to be
                  shredded mid-word at 390px where the French ones fit. */}
              <td className="keep-words">
                {role.permissions.length === data.catalog.length
                  ? t("all")
                  : role.permissions.map((p) => permLabel(t, p)).join(", ")}
              </td>
              <td>
                <RoleActionsCell
                  role={role}
                  manage={manage}
                  ownRole={ownRole}
                  onEdit={() => { setSaved(""); mutation.clear(); setEditing({ role }); }}
                  onRemove={() => remove(role)}
                />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {editing && (
        <RoleDialog
          catalog={data.catalog}
          existing={editing.role}
          taken={data.items.map((r) => r.name)}
          close={() => setEditing(null)}
          done={(message) => { setSaved(message); setEditing(null); reload(); }}
        />
      )}
      {inUse && (
        <RoleInUseDialog
          role={inUse}
          roles={data.items}
          close={() => setInUse(null)}
          deleted={() => { setInUse(null); setSaved(t("roleDeleted")); reload(); }}
        />
      )}
    </div>
  );
}

function RoleActionsCell({
  role,
  manage,
  ownRole,
  onEdit,
  onRemove,
}: Readonly<{
  role: Role;
  manage: boolean;
  ownRole: string;
  onEdit: () => void;
  onRemove: () => void;
}>) {
  const t = useText();
  if (role.builtin) {
    return (
      <span className="muted readonly-cell">
        <Icon name="lock" />
        {t("readOnly2")}
      </span>
    );
  }
  if (!manage) return <span className="muted">—</span>;
  return (
    <div className="row-actions">
      <button className="button secondary small" onClick={onEdit}>
        <Icon name="settings" />
        {t("edit")}
      </button>
      <button
        className="button danger small"
        disabled={role.name === ownRole}
        title={role.name === ownRole ? t("youCannotDeleteTheRoleYou") : undefined}
        onClick={onRemove}
      >
        <Icon name="trash" />
        {t("delete")}
      </button>
    </div>
  );
}

/**
 * Shown when deleting a role is refused because members still hold it: it lists
 * those members and offers the two ways out — reassign to another role, or
 * remove the member's access — then lets the deletion be retried.
 */
function RoleInUseDialog({
  role,
  roles,
  close,
  deleted,
}: Readonly<{
  role: Role;
  roles: Role[];
  close: () => void;
  deleted: () => void;
}>) {
  const t = useText();
  const { session } = useContext(Context);
  const holders = useResource<RoleMembersResponse>(
    `/api/roles/${encodeURIComponent(role.name)}/members`,
  );
  const mutation = useMutation();
  const manageMembers = canManage(session);
  const replacements = roles.map((r) => r.name).filter((name) => name !== role.name);
  const [target, setTarget] = useState<Record<string, string>>({});

  async function reassign(member: RoleMember) {
    const next = target[member.id] ?? replacements[0];
    if (!next) return;
    try {
      await mutation.run(`/api/members/${member.id}/role`, "PUT", { role: next });
      holders.reload();
    } catch {
      /* Displayed via mutation.error below. */
    }
  }

  async function detach(member: RoleMember) {
    try {
      await mutation.run(`/api/members/${member.id}`, "DELETE");
      holders.reload();
    } catch {
      /* Displayed via mutation.error below. */
    }
  }

  async function retryDelete() {
    try {
      await mutation.run(`/api/roles/${encodeURIComponent(role.name)}`, "DELETE");
      deleted();
    } catch {
      /* Displayed via mutation.error below. */
    }
  }

  return (
    <Dialog title={t("roleHeldByMembers")} close={close}>
      <Notice tone="warning">
        {t("theRole0CannotBeDeleted", [role.name])}
      </Notice>
      {!manageMembers && (
        <Notice tone="warning">
          {t("youCannotManageMembersAskA")}
        </Notice>
      )}
      <ErrorNotice error={mutation.error} />
      <ResourceView resource={holders}>
        {(data) =>
          data.items.length === 0 ? (
            <p className="muted">{t("noMemberHoldsThisRoleAny")}</p>
          ) : (
            <>
              <table>
                <thead>
                  <tr>
                    <th>{t("member")}</th>
                    <th>{t("emailAddress")}</th>
                    <th>{t("actions")}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((member) => (
                    <tr key={member.id}>
                      <td>
                        <strong>{member.display_name || "—"}</strong>
                      </td>
                      <td>{member.email}</td>
                      <td>
                        {manageMembers && member.id !== session.user.id ? (
                          <div className="row-actions">
                            <select
                              aria-label={t("newRoleFor0", [member.email])}
                              value={target[member.id] ?? replacements[0] ?? ""}
                              onChange={(e) => setTarget((current) => ({ ...current, [member.id]: e.target.value }))}
                            >
                              {replacements.map((name) => (
                                <option key={name} value={name}>
                                  {name}
                                </option>
                              ))}
                            </select>
                            <button
                              className="button secondary small"
                              disabled={mutation.pending || replacements.length === 0}
                              onClick={() => reassign(member)}
                            >
                              <Icon name="shield" />
                              {t("reassign")}
                            </button>
                            <button
                              className="button danger small"
                              disabled={mutation.pending}
                              onClick={() => detach(member)}
                            >
                              <Icon name="trash" />
                              {t("removeAccess")}
                            </button>
                          </div>
                        ) : (
                          <span
                            className="muted readonly-cell"
                            title={
                              member.id === session.user.id
                                ? t("thisIsYouYouCannotChange")
                                : t("readOnly")
                            }
                          >
                            <Icon name="lock" />
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {data.total > data.items.length && (
                <p className="muted">
                  {t("n0MembersHoldThisRoleThe", [data.total, data.items.length])}
                </p>
              )}
            </>
          )
        }
      </ResourceView>
      <div className="dialog-actions">
        <button type="button" className="button secondary" onClick={close}>
          {t("close")}
        </button>
        <button
          type="button"
          className="button danger"
          disabled={mutation.pending || holders.data === undefined || holders.data.total > 0}
          title={
            holders.data && holders.data.total > 0
              ? t("membersStillHoldThisRole")
              : undefined
          }
          onClick={retryDelete}
        >
          <Icon name="trash" />
          {t("deleteRole")}
        </button>
      </div>
    </Dialog>
  );
}

function RoleDialog({
  catalog,
  existing,
  taken,
  close,
  done,
}: Readonly<{
  catalog: string[];
  existing?: Role;
  taken: string[];
  close: () => void;
  done: (message: string) => void;
}>) {
  const t = useText();
  const mutation = useMutation();
  const [name, setName] = useState(existing?.name ?? "");
  const [permissions, setPermissions] = useState<string[]>(existing?.permissions ?? []);
  const isNew = !existing;

  function toggle(permission: string, on: boolean) {
    setPermissions((current) =>
      on ? [...new Set([...current, permission])] : current.filter((p) => p !== permission),
    );
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    try {
      if (isNew) {
        await mutation.run("/api/roles", "POST", { name: name.trim(), permissions });
      } else {
        await mutation.run(`/api/roles/${encodeURIComponent(existing!.name)}`, "PUT", { permissions });
      }
      done(t("roleSaved"));
    } catch {
      /* Displayed via mutation.error below. */
    }
  }

  const duplicate = isNew && taken.includes(name.trim());
  return (
    <Dialog title={isNew ? t("newRole") : t("editRole")} close={close}>
      <form onSubmit={save}>
        {isNew ? (
          <label>
            {t("roleName")}
            <input required maxLength={60} value={name} onChange={(e) => setName(e.target.value)} />
          </label>
        ) : (
          <p>
            <span className="role-badge">{existing!.name}</span>
          </p>
        )}
        {duplicate && <Notice tone="warning">{t("thisNameIsAlreadyUsed")}</Notice>}
        <fieldset disabled={mutation.pending}>
          <legend>{t("permissions2")}</legend>
          {catalog.map((permission) => (
            <label className="checkbox-label" key={permission}>
              <input
                type="checkbox"
                checked={permissions.includes(permission)}
                onChange={(e) => toggle(permission, e.target.checked)}
              />
              <span>{permLabel(t, permission)}</span>
            </label>
          ))}
        </fieldset>
        <ErrorNotice error={mutation.error} />
        <div className="dialog-actions">
          <button type="button" className="button secondary" onClick={close}>
            {t("cancel")}
          </button>
          <button type="submit" className="button primary" disabled={mutation.pending || (isNew && (!name.trim() || duplicate))}>
            {mutation.pending ? t("saving") : t("save")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
