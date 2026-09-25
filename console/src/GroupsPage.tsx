import { useContext, useEffect, useRef, useState } from "react";
import type { SubmitEvent } from "react";
import type { Device, DeviceGroup } from "./api";
import { ScopedSettings } from "./shadow/ShadowAdministration";
import {
  Button,
  Card,
  Context,
  DateValue,
  Dialog,
  Empty,
  ErrorNotice,
  Icon,
  Notice,
  PageBar,
  PageNumbers,
  PageSize,
  RefreshButton,
  ResourceView,
  Status,
  Tabs,
  can,
  useBoundedPage,
  idFromHash,
  useMutation,
  useResource,
  useText,
} from "./ui";

type GroupArea = "details" | "policy";

// A device group names a set of devices that share one Shadow AI override. The
// list and the detail page live under #groups and #groups?id=<uuid>, on the
// model of the devices page; the success message and the dialogs sit above the
// ResourceView so a reload never unmounts them.
export function GroupsPage() {
  const t = useText();
  const { session } = useContext(Context);
  const groups = useResource<{ items: DeviceGroup[] }>("/api/groups");
  const deletion = useMutation();
  const [id, setId] = useState(idFromHash);
  const [area, setArea] = useState<GroupArea>("details");
  const [success, setSuccess] = useState("");
  const [failures, setFailures] = useState<string[]>([]);
  const [create, setCreate] = useState(false);
  const [edit, setEdit] = useState<DeviceGroup>();
  const [remove, setRemove] = useState<DeviceGroup>();
  const manage = can(session, "devices.manage");
  // Deleting the open group returns to the list; that navigation must not wipe
  // the confirmation it just produced.
  const keepSuccess = useRef(false);
  useEffect(() => {
    const changed = () => {
      setId(idFromHash());
      if (keepSuccess.current) keepSuccess.current = false;
      else setSuccess("");
      setFailures([]);
      setArea("details");
    };
    window.addEventListener("hashchange", changed);
    return () => window.removeEventListener("hashchange", changed);
  }, []);
  function notify(message: string, failed: string[]) {
    setSuccess(message);
    setFailures(failed);
  }
  async function del(group: DeviceGroup) {
    try {
      await deletion.run(`/api/groups/${encodeURIComponent(group.id)}`, "DELETE");
      setRemove(undefined);
      setSuccess(t("groupDeleted"));
      setFailures([]);
      groups.reload();
      if (id === group.id) {
        keepSuccess.current = true;
        window.location.hash = "#groups";
      }
    } catch {
      /* Displayed by ErrorNotice inside the dialog. */
    }
  }
  return (
    <>
      {!id && (
        <PageBar
          title={t("deviceGroups")}
          actions={
            <>
              <RefreshButton onClick={groups.reload} />
              {manage && (
                <Button variant="primary" icon="plus" onClick={() => setCreate(true)}>
                  {t("newGroup")}
                </Button>
              )}
            </>
          }
          info={t("aGroupAppliesOneShadowAi")}
        />
      )}
      {success && (
        <output className="notice success">
          <Icon name="check" />
          {success}
        </output>
      )}
      {failures.length > 0 && (
        <Notice tone="danger" role="alert">
          {t("couldNotUpdate") + failures.join(", ")}
        </Notice>
      )}
      <ResourceView resource={groups}>
        {(data) => {
          if (id) {
            const group = data.items.find((item) => item.id === id);
            if (!group) {
              return (
                <>
                  <PageBar
                    title={t("group")}
                    actions={
                      <a className="button secondary" href="#groups">
                        {t("backToGroups")}
                      </a>
                    }
                  />
                  <Empty title={t("groupNotFound")}>{t("thisGroupDoesNotExistOr")}</Empty>
                </>
              );
            }
            return (
              <GroupDetail
                group={group}
                area={area}
                setArea={setArea}
                reload={groups.reload}
                rename={() => setEdit(group)}
                remove={() => {
                  deletion.clear();
                  setRemove(group);
                }}
                notify={notify}
              />
            );
          }
          return (
            <section className="panel table-panel">
              <div className="section-heading">
                <div>
                  <h2>{t("deviceGroups")}</h2>
                  <p>{t("theGroupsOverridesApplyToIts")}</p>
                </div>
                <div className="row-actions">
                  <span className="count-badge">{data.items.length}</span>
                </div>
              </div>
              {data.items.length === 0 ? (
                <Empty title={t("noGroupsYet")}>{t("aGroupAppliesOneShadowAi")}</Empty>
              ) : (
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        {[t("name"), t("groupDescription"), t("devices"), t("actions")].map((label) => (
                          <th key={label}>{label}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {data.items.map((group) => (
                        <tr key={group.id}>
                          <td className="nowrap">
                            <a href={`#groups?id=${group.id}`}>
                              <strong>{group.name}</strong>
                            </a>
                          </td>
                          <td>{group.description || <span className="muted">—</span>}</td>
                          <td>{group.device_count}</td>
                          <td>
                            <div className="row-actions">
                              {manage ? (
                                <>
                                  <Button size="small" icon="settings" onClick={() => setEdit(group)}>
                                    {t("rename")}
                                  </Button>
                                  <Button
                                    size="small"
                                    variant="danger"
                                    icon="trash"
                                    onClick={() => {
                                      deletion.clear();
                                      setRemove(group);
                                    }}
                                  >
                                    {t("delete")}
                                  </Button>
                                </>
                              ) : (
                                <span className="muted">—</span>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          );
        }}
      </ResourceView>
      {create && (
        <GroupDialog
          title={t("newGroup")}
          submit={t("createGroup")}
          path="/api/groups"
          method="POST"
          done={() => {
            setCreate(false);
            setSuccess(t("groupCreated"));
            setFailures([]);
            groups.reload();
          }}
          close={() => setCreate(false)}
        />
      )}
      {edit && (
        <GroupDialog
          title={t("renameGroup")}
          submit={t("save")}
          path={`/api/groups/${encodeURIComponent(edit.id)}`}
          method="PUT"
          initial={edit}
          done={() => {
            setEdit(undefined);
            setSuccess(t("groupUpdated"));
            setFailures([]);
            groups.reload();
          }}
          close={() => setEdit(undefined)}
        />
      )}
      {remove && (
        <Dialog title={t("deleteGroup")} close={() => !deletion.pending && setRemove(undefined)}>
          <p>{t("devicesOfADeletedGroupFallBack")}</p>
          <ul className="confirm-list">
            <li>
              <strong>{remove.name}</strong> · {remove.device_count === 1 ? t("oneDevice") : t("nDevices", [remove.device_count])}
            </li>
          </ul>
          <ErrorNotice error={deletion.error} />
          <div className="dialog-actions">
            <button type="button" className="button secondary" disabled={deletion.pending} onClick={() => setRemove(undefined)}>
              {t("cancel")}
            </button>
            <button type="button" className="button danger" disabled={deletion.pending} onClick={() => void del(remove)}>
              {t("confirmDeletion")}
            </button>
          </div>
        </Dialog>
      )}
    </>
  );
}

// Create or rename a group. The dialog owns its request so its error shows next
// to the fields, and hands the saved group back to the page.
function GroupDialog({ title, submit, path, method, initial, done, close }: Readonly<{ title: string; submit: string; path: string; method: "POST" | "PUT"; initial?: DeviceGroup; done: (group: DeviceGroup) => void; close: () => void }>) {
  const t = useText();
  const mutation = useMutation();
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  async function save(event: SubmitEvent) {
    event.preventDefault();
    try {
      const group = await mutation.run<DeviceGroup>(path, method, { name: name.trim(), description: description.trim() });
      if (group) done(group);
    } catch {
      /* Displayed by ErrorNotice. */
    }
  }
  return (
    <Dialog title={title} close={() => !mutation.pending && close()}>
      <form onSubmit={save}>
        <label>
          {t("groupName")}
          <input required maxLength={80} value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label>
          {t("groupDescription")}
          <input maxLength={300} value={description} onChange={(e) => setDescription(e.target.value)} />
        </label>
        <ErrorNotice error={mutation.error} />
        <div className="dialog-actions">
          <button type="button" className="button secondary" disabled={mutation.pending} onClick={close}>
            {t("cancel")}
          </button>
          <button type="submit" className="button primary" disabled={mutation.pending || !name.trim()}>
            {submit}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

function GroupDetail({ group, area, setArea, reload, rename, remove, notify }: Readonly<{ group: DeviceGroup; area: GroupArea; setArea: (area: GroupArea) => void; reload: () => void; rename: () => void; remove: () => void; notify: (message: string, failed: string[]) => void }>) {
  const t = useText();
  const { session } = useContext(Context);
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(50);
  const devicePath = `/api/devices?group_id=${encodeURIComponent(group.id)}&limit=${size}&offset=${(page - 1) * size}`;
  const devices = useResource<{ items: Device[]; total?: number }>(devicePath);
  const { current: currentPage, pages: pageCount } = useBoundedPage(page, setPage, size, devices.data?.total ?? devices.data?.items.length);
  const mutation = useMutation();
  const [adding, setAdding] = useState(false);
  const manage = can(session, "devices.manage");
  const areas: GroupArea[] = ["details", ...(can(session, "policy.manage") ? (["policy"] as GroupArea[]) : [])];
  const current = areas.includes(area) ? area : "details";
  // One request per device, like the bulk actions elsewhere: a refused device is
  // reported by name instead of aborting the others.
  async function assign(targets: Device[], groupId: string | null) {
    const failed: string[] = [];
    for (const device of targets) {
      try {
        await mutation.run(`/api/devices/${encodeURIComponent(device.id)}/group`, "PUT", { group_id: groupId });
      } catch {
        failed.push(device.hostname || t("machineNameUnavailable"));
      }
    }
    notify(failed.length < targets.length ? t("deviceGroupUpdated") : "", failed);
    setAdding(false);
    devices.reload();
    reload();
  }
  return (
    <>
      <PageBar
        title={group.name}
        actions={
          <>
            <a className="button secondary" href="#groups">
              {t("backToGroups")}
            </a>
            <RefreshButton
              onClick={() => {
                devices.reload();
                reload();
              }}
            />
            {manage && (
              <Button icon="settings" onClick={rename}>
                {t("rename")}
              </Button>
            )}
            {manage && (
              <Button variant="danger" icon="trash" onClick={remove}>
                {t("delete")}
              </Button>
            )}
          </>
        }
        info={group.description || t("aGroupAppliesOneShadowAi")}
      />
      {areas.length > 1 && (
        <Tabs
          label={t("groupSections")}
          selected={current}
          onSelect={(value) => setArea(value as GroupArea)}
          items={areas.map((item) => ({ id: item, name: item === "details" ? t("details") : t("groupPolicy") }))}
        />
      )}
      {current === "details" && (
        <>
          <Card title={t("details")}>
            <dl className="dl">
              <dt>{t("identifier")}</dt>
              <dd>
                <span className="mono">{group.id}</span>
              </dd>
              <dt>{t("groupDescription")}</dt>
              <dd>{group.description || <span className="muted">—</span>}</dd>
              <dt>{t("devices")}</dt>
              <dd>{group.device_count === 1 ? t("oneDevice") : t("nDevices", [group.device_count])}</dd>
            </dl>
          </Card>
          <section className="panel table-panel">
            <div className="section-heading">
              <div>
                <h2>{t("devices")}</h2>
                <p>{t("theGroupsOverridesApplyToIts")}</p>
              </div>
              <div className="row-actions">
                <PageSize value={size} label={t("perPage")} change={(value) => { setSize(value); setPage(1); }} />
                {manage && (
                  <Button variant="primary" icon="plus" disabled={mutation.pending} onClick={() => setAdding(true)}>
                    {t("addDevices")}
                  </Button>
                )}
              </div>
            </div>
            <ResourceView resource={devices}>
              {(data) => {
                const members = data.items.filter((device) => device.group_id === group.id);
                return members.length === 0 ? (
                  <Empty title={t("noDeviceInThisGroup")} />
                ) : (
                  <>
                    <div className="table-scroll">
                      <table>
                      <thead>
                        <tr>
                          {[t("device"), t("platform"), t("status"), t("lastSeen"), t("actions")].map((label) => (
                            <th key={label}>{label}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {members.map((device) => (
                          <tr key={device.id}>
                            <td>
                              <a href={`#devices?id=${device.id}`}>
                                <strong>{device.hostname || t("machineNameUnavailable")}</strong>
                              </a>
                            </td>
                            <td>{device.platform}</td>
                            <td>
                              <Status value={device.status} />
                            </td>
                            <td className="nowrap">
                              <DateValue value={device.last_seen} />
                            </td>
                            <td>
                              {manage ? (
                                <Button size="small" variant="danger" icon="trash" disabled={mutation.pending} onClick={() => void assign([device], null)}>
                                  {t("removeFromGroup")}
                                </Button>
                              ) : (
                                <span className="muted">—</span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                      </table>
                    </div>
                    <PageNumbers page={currentPage} pages={pageCount} go={setPage} label={t("pagination")} />
                  </>
                );
              }}
            </ResourceView>
          </section>
          {adding && (
            <AddDevicesDialog
              groupId={group.id}
              pending={mutation.pending}
              close={() => !mutation.pending && setAdding(false)}
              confirm={(targets) => void assign(targets, group.id)}
            />
          )}
        </>
      )}
      {current === "policy" && (
        <>
          <div className="section-heading">
            <div>
              <h2>{t("groupPolicy")}</h2>
              <p>{t("theGroupsOverridesApplyToIts")}</p>
            </div>
          </div>
          <ScopedSettings device="" group={group.id} />
        </>
      )}
    </>
  );
}

// Pick devices to move into the group. A device already in another group is
// listed with that group's name, because moving it is a change worth seeing.
function AddDevicesDialog({ groupId, pending, close, confirm }: Readonly<{ groupId: string; pending: boolean; close: () => void; confirm: (targets: Device[]) => void }>) {
  const t = useText();
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(50);
  const candidates = useResource<{ items: Device[]; total?: number }>(`/api/devices?exclude_group_id=${encodeURIComponent(groupId)}&limit=${size}&offset=${(page - 1) * size}`);
  const { current: currentPage, pages: pageCount } = useBoundedPage(page, setPage, size, candidates.data?.total ?? candidates.data?.items.length);
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const selected = useRef(new Map<string, Device>());
  return (
    <Dialog title={t("addDevices")} close={close} side="right">
      <div className="dialog-body">
        <ResourceView resource={candidates}>
          {(data) => {
            const visible = data.items.filter((device) => device.group_id !== groupId);
            return visible.length === 0 ? (
            <Empty title={t("allDevicesAlreadyBelongTo")} />
          ) : (
            <>
              <PageSize value={size} label={t("perPage")} change={(value) => { setSize(value); setPage(1); }} />
              <ul className="confirm-list">
                {visible.map((device) => (
              <li key={device.id}>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={chosen.has(device.id)}
                    onChange={(e) => {
                      const checked = e.target.checked;
                      if (checked) selected.current.set(device.id, device);
                      else selected.current.delete(device.id);
                      setChosen((current) => {
                        const next = new Set(current);
                        if (checked) next.add(device.id);
                        else next.delete(device.id);
                        return next;
                      });
                    }}
                  />
                  <span>
                    {device.hostname || t("machineNameUnavailable")}
                    {device.group_name && <small> · {device.group_name}</small>}
                  </span>
                </label>
              </li>
                ))}
              </ul>
              <PageNumbers page={currentPage} pages={pageCount} go={setPage} label={t("pagination")} />
            </>
          );
          }}
        </ResourceView>
      </div>
      <div className="dialog-actions">
        <button type="button" className="button secondary" disabled={pending} onClick={close}>
          {t("cancel")}
        </button>
        <button type="button" className="button primary" disabled={pending || chosen.size === 0} onClick={() => confirm([...selected.current.values()])}>
          {t("addNDevices", [chosen.size])}
        </button>
      </div>
    </Dialog>
  );
}
