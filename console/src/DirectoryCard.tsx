import { useState } from "react";
import type { SubmitEvent } from "react";
import type { LdapDirectory } from "./api";
import {
  Button,
  Card,
  Dialog,
  ErrorNotice,
  Field,
  Notice,
  ResourceView,
  useMutation,
  useResource,
  useText,
} from "./ui";

type Vendor = "ad" | "rhds" | "tivoli" | "edirectory" | "other";

type DirectoryForm = {
  name: string;
  vendor: Vendor;
  connection_url: string;
  auth_type: "simple" | "none";
  bind_dn: string;
  bind_credential: string;
  users_dn: string;
  username_attribute: string;
  rdn_attribute: string;
  uuid_attribute: string;
  user_object_classes: string;
  custom_filter: string;
  search_scope: 1 | 2;
  start_tls: boolean;
  use_truststore: "always" | "never";
  connection_timeout_ms: number;
  read_timeout_ms: number;
  pagination: boolean;
};

type VendorObjects = Pick<
  DirectoryForm,
  | "username_attribute"
  | "rdn_attribute"
  | "uuid_attribute"
  | "user_object_classes"
>;

// Naming conventions of each directory product. Selecting a vendor prefills
// these four fields; the server accepts any valid attribute name, so an
// operator can still adjust them for a customized schema.
const vendorObjects: Record<Vendor, VendorObjects> = {
  ad: {
    username_attribute: "cn",
    rdn_attribute: "cn",
    uuid_attribute: "objectGUID",
    user_object_classes: "person, organizationalPerson, user",
  },
  rhds: {
    username_attribute: "uid",
    rdn_attribute: "uid",
    uuid_attribute: "nsuniqueid",
    user_object_classes: "inetOrgPerson, organizationalPerson",
  },
  tivoli: {
    username_attribute: "uid",
    rdn_attribute: "uid",
    uuid_attribute: "uniqueidentifier",
    user_object_classes: "inetOrgPerson, organizationalPerson",
  },
  edirectory: {
    username_attribute: "uid",
    rdn_attribute: "uid",
    uuid_attribute: "guid",
    user_object_classes: "inetOrgPerson, organizationalPerson",
  },
  other: {
    username_attribute: "uid",
    rdn_attribute: "uid",
    uuid_attribute: "entryUUID",
    user_object_classes: "inetOrgPerson, organizationalPerson",
  },
};

const defaultForm: DirectoryForm = {
  name: "",
  vendor: "other",
  connection_url: "",
  auth_type: "simple",
  bind_dn: "",
  bind_credential: "",
  users_dn: "",
  ...vendorObjects.other,
  custom_filter: "",
  search_scope: 2,
  start_tls: false,
  use_truststore: "never",
  connection_timeout_ms: 5000,
  read_timeout_ms: 10000,
  pagination: true,
};

function fromData(data: LdapDirectory): DirectoryForm {
  if (!data.configured) return defaultForm;
  return {
    name: data.name,
    vendor: data.vendor,
    connection_url: data.connection_url,
    auth_type: data.auth_type,
    bind_dn: data.bind_dn,
    bind_credential: "",
    users_dn: data.users_dn,
    username_attribute: data.username_attribute,
    rdn_attribute: data.rdn_attribute,
    uuid_attribute: data.uuid_attribute,
    user_object_classes: data.user_object_classes,
    custom_filter: data.custom_filter,
    search_scope: data.search_scope,
    start_tls: data.start_tls,
    use_truststore: data.use_truststore,
    connection_timeout_ms: data.connection_timeout_ms,
    read_timeout_ms: data.read_timeout_ms,
    pagination: data.pagination,
  };
}

type NoticeState = { tone: "success" | "danger"; text: string };

export function DirectoryCard() {
  const t = useText();
  const resource = useResource<LdapDirectory>("/api/settings/ldap");
  // Lives here, not in the child: reload() unmounts that child, and its state would go with it.
  const [notice, setNotice] = useState<NoticeState | null>(null);
  return (
    <Card
      title={t("ldapDirectory")}
      description={t("letsDirectoryUsersSignInThey")}
    >
      {notice && <Notice tone={notice.tone}>{notice.text}</Notice>}
      <ResourceView resource={resource}>
        {(data) => data.editable === false ? (
          <Notice>{t(data.configured ? "ldapOperatorManagedConfigured" : "ldapOperatorManaged")}</Notice>
        ) : (
          <DirectoryEditor
            data={data}
            reload={resource.reload}
            notify={(tone, text) => setNotice({ tone, text })}
          />
        )}
      </ResourceView>
    </Card>
  );
}

function DirectoryEditor({
  data,
  reload,
  notify,
}: Readonly<{
  data: LdapDirectory;
  reload: () => void;
  notify: (tone: "success" | "danger", text: string) => void;
}>) {
  const t = useText();
  const [form, setForm] = useState<DirectoryForm>(() => fromData(data));
  const [testResult, setTestResult] = useState<NoticeState | null>(null);
  const [removing, setRemoving] = useState(false);
  const testMutation = useMutation();
  const saveMutation = useMutation();
  const pending = testMutation.pending || saveMutation.pending;

  function set<K extends keyof DirectoryForm>(key: K, value: DirectoryForm[K]) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  // Changing the vendor realigns the schema fields on that product's
  // conventions, as an operator switching product expects.
  function selectVendor(vendor: Vendor) {
    setForm((current) => ({ ...current, vendor, ...vendorObjects[vendor] }));
  }

  async function test() {
    setTestResult(null);
    try {
      const result = await testMutation.run<{
        ok: boolean;
        step: string;
        message?: string;
      }>("/api/settings/ldap/test", "POST", form);
      if (!result) return;
      setTestResult(
        result.ok
          ? {
              tone: "success",
              text: t("connectionAndAuthenticationSucceeded"),
            }
          : {
              tone: "danger",
              text: `${t("stepFailed")} ${result.step}${result.message ? " : " + result.message : ""}`,
            },
      );
    } catch {
      /* Displayed via testMutation.error below. */
    }
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    try {
      await saveMutation.run("/api/settings/ldap", "PUT", form);
      notify(
        "success",
        t("directorySavedLdapSignInIs"),
      );
      reload();
    } catch {
      /* Displayed via saveMutation.error below. */
    }
  }

  return (
    <>
      <form onSubmit={save}>
        <fieldset disabled={pending}>
          <div className="directory-fields">
            <Field label={t("directoryName")}>
              <input
                required
                maxLength={120}
                value={form.name}
                onChange={(e) => set("name", e.target.value)}
              />
            </Field>
            <Field
              label={t("directoryVendor")}
              help={t("theAttributesAndObjectClassesBelow")}
            >
              <select
                value={form.vendor}
                onChange={(e) => selectVendor(e.target.value as Vendor)}
              >
                <option value="ad">Active Directory</option>
                <option value="rhds">Red Hat Directory Server</option>
                <option value="tivoli">IBM Tivoli</option>
                <option value="edirectory">Novell eDirectory</option>
                <option value="other">{t("other")}</option>
              </select>
            </Field>
            <Field label={t("connectionUrl")}>
              <input
                required
                placeholder="ldaps://annuaire.exemple.local:636"
                value={form.connection_url}
                onChange={(e) => set("connection_url", e.target.value)}
              />
            </Field>
            <Field label={t("authenticationType")}>
              <select
                value={form.auth_type}
                onChange={(e) => set("auth_type", e.target.value as DirectoryForm["auth_type"])}
              >
                <option value="simple">{t("simple")}</option>
                <option value="none">{t("anonymous")}</option>
              </select>
            </Field>
            <Field label={t("bindDn")}>
              <input
                disabled={form.auth_type === "none"}
                value={form.bind_dn}
                onChange={(e) => set("bind_dn", e.target.value)}
              />
            </Field>
            <Field
              label={t("bindPassword")}
              help={
                data.configured
                  ? t("leaveBlankToKeepTheStored")
                  : undefined
              }
            >
              <input
                type="password"
                autoComplete="off"
                value={form.bind_credential}
                onChange={(e) => set("bind_credential", e.target.value)}
              />
            </Field>
            <Field label={t("usersDn")}>
              <input
                required
                value={form.users_dn}
                onChange={(e) => set("users_dn", e.target.value)}
              />
            </Field>
            <Field label={t("usernameAttribute")}>
              <input
                required
                value={form.username_attribute}
                onChange={(e) => set("username_attribute", e.target.value)}
              />
            </Field>
            <Field label={t("rdnAttribute")}>
              <input
                required
                value={form.rdn_attribute}
                onChange={(e) => set("rdn_attribute", e.target.value)}
              />
            </Field>
            <Field label={t("uuidAttribute")}>
              <input
                required
                value={form.uuid_attribute}
                onChange={(e) => set("uuid_attribute", e.target.value)}
              />
            </Field>
            <Field label={t("userObjectClasses")}>
              <input
                required
                value={form.user_object_classes}
                onChange={(e) => set("user_object_classes", e.target.value)}
              />
            </Field>
            <Field label={t("customFilter")}>
              <input
                value={form.custom_filter}
                onChange={(e) => set("custom_filter", e.target.value)}
              />
            </Field>
            <Field label={t("searchScope")}>
              <select
                value={form.search_scope}
                onChange={(e) => set("search_scope", Number(e.target.value) as 1 | 2)}
              >
                <option value={1}>{t("oneLevel")}</option>
                <option value={2}>{t("subtree")}</option>
              </select>
            </Field>
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={form.start_tls}
                onChange={(e) => set("start_tls", e.target.checked)}
              />
              <span>StartTLS</span>
            </label>
            <Field label={t("truststore")}>
              <select
                value={form.use_truststore}
                onChange={(e) => set("use_truststore", e.target.value as DirectoryForm["use_truststore"])}
              >
                <option value="always">{t("always")}</option>
                <option value="never">{t("never")}</option>
              </select>
            </Field>
            <Field label={t("connectionTimeoutMs")}>
              <input
                type="number"
                min={0}
                max={300000}
                value={form.connection_timeout_ms}
                onChange={(e) => set("connection_timeout_ms", Number(e.target.value))}
              />
            </Field>
            <Field label={t("readTimeoutMs")}>
              <input
                type="number"
                min={0}
                max={300000}
                value={form.read_timeout_ms}
                onChange={(e) => set("read_timeout_ms", Number(e.target.value))}
              />
            </Field>
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={form.pagination}
                onChange={(e) => set("pagination", e.target.checked)}
              />
              <span>{t("pagination")}</span>
            </label>
          </div>
        </fieldset>
        {testResult && <Notice tone={testResult.tone}>{testResult.text}</Notice>}
        <ErrorNotice error={testMutation.error ?? saveMutation.error} />
        <div className="dialog-actions">
          <Button variant="secondary" type="button" disabled={pending} onClick={() => void test()}>
            {t("testConnection")}
          </Button>
          <Button variant="primary" type="submit" disabled={pending}>
            {t("saveDirectory")}
          </Button>
          {data.configured && (
            <Button
              variant="danger"
              type="button"
              disabled={pending}
              onClick={() => setRemoving(true)}
            >
              {t("removeDirectory")}
            </Button>
          )}
        </div>
      </form>
      {removing && (
        <RemoveDirectoryDialog
          close={() => setRemoving(false)}
          done={() => {
            setRemoving(false);
            notify("success", t("directoryRemoved"));
            reload();
          }}
        />
      )}
    </>
  );
}

function RemoveDirectoryDialog({
  close,
  done,
}: Readonly<{
  close: () => void;
  done: () => void;
}>) {
  const t = useText();
  const mutation = useMutation();
  async function remove() {
    try {
      await mutation.run("/api/settings/ldap", "DELETE");
      done();
    } catch {
      /* Displayed via mutation.error below. */
    }
  }
  return (
    <Dialog
      title={t("removeDirectory")}
      close={() => !mutation.pending && close()}
    >
      <p>
        {t("usersOfThisDirectoryWillNo")}
      </p>
      <ErrorNotice error={mutation.error} />
      <div className="dialog-actions">
        <Button variant="secondary" disabled={mutation.pending} onClick={close}>
          {t("cancel")}
        </Button>
        <Button variant="danger" disabled={mutation.pending} onClick={() => void remove()}>
          {t("confirmRemoval2")}
        </Button>
      </div>
    </Dialog>
  );
}
