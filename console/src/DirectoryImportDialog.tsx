import { useContext, useState } from "react";
import type { SubmitEvent } from "react";
import type { DirectoryUser } from "./api";
import {
  Context,
  Dialog,
  ErrorNotice,
  Notice,
  useMutation,
  useText,
} from "./ui";
import type { Translate } from "./ui";

function roleLabel(t: Translate, name: string) {
  if (name === "owner") return t("owner");
  if (name === "admin") return t("administrator");
  if (name === "viewer") return t("viewer");
  return name;
}

export function DirectoryImportDialog({
  roles,
  close,
  done,
}: Readonly<{
  roles: string[];
  close: () => void;
  done: () => void;
}>) {
  const t = useText();
  const { session } = useContext(Context);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<DirectoryUser[] | null>(null);
  const [subject, setSubject] = useState("");
  const [role, setRole] = useState("viewer");
  const [imported, setImported] = useState(false);
  const search = useMutation();
  const importMutation = useMutation();

  async function runSearch(e: SubmitEvent) {
    e.preventDefault();
    setResults(null);
    setSubject("");
    try {
      const found = await search.run<{ items: DirectoryUser[] }>(
        `/api/members/directory?query=${encodeURIComponent(query)}`,
        "GET",
      );
      setResults(found?.items ?? []);
    } catch {
      /* Displayed via search.error below. */
    }
  }

  async function importMember(e: SubmitEvent) {
    e.preventDefault();
    try {
      await importMutation.run("/api/members/directory", "POST", {
        subject,
        role,
      });
      setImported(true);
      done();
    } catch {
      /* Displayed via importMutation.error below. */
    }
  }

  const availableRoles = roles.filter(
    (r) => r !== "owner" || session.organization.role === "owner",
  );

  return (
    <Dialog
      title={t("importFromDirectory")}
      close={() => !(search.pending || importMutation.pending) && close()}
    >
      {imported && (
        <Notice tone="success" role="status">
          {t("memberImportedFromTheDirectory")}
        </Notice>
      )}
      <form onSubmit={runSearch}>
        <label>
          {t("searchTheDirectory")}
          <input
            required
            minLength={2}
            maxLength={64}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </label>
        <ErrorNotice error={search.error} />
        <div className="dialog-actions">
          <button type="submit" className="button secondary" disabled={search.pending}>
            {search.pending
              ? t("searching")
              : t("search")}
          </button>
        </div>
      </form>
      {results && (
        <form onSubmit={importMember}>
          <fieldset disabled={importMutation.pending}>
            <legend>{t("results")}</legend>
            {results.length === 0 ? (
              <p className="muted">
                {t("noUserFound")}
              </p>
            ) : (
              results.map((user) => (
                <label
                  key={user.subject}
                  className="checkbox-label"
                  title={
                    !user.email
                      ? t("noEmailAddressInTheDirectory")
                      : undefined
                  }
                >
                  <input
                    type="radio"
                    name="directory-user"
                    value={user.subject}
                    disabled={!user.email}
                    checked={subject === user.subject}
                    onChange={() => setSubject(user.subject)}
                  />
                  <span>
                    {(user.display_name || user.username) + " · " + user.email}
                  </span>
                </label>
              ))
            )}
          </fieldset>
          {results.length > 0 && (
            <label>
              {t("role")}
              <select value={role} onChange={(e) => setRole(e.target.value)}>
                {availableRoles.map((r) => (
                  <option key={r} value={r}>
                    {roleLabel(t, r)}
                  </option>
                ))}
              </select>
            </label>
          )}
          <ErrorNotice error={importMutation.error} />
          <div className="dialog-actions">
            <button
              type="button"
              className="button secondary"
              disabled={importMutation.pending}
              onClick={close}
            >
              {t("cancel")}
            </button>
            <button
              type="submit"
              className="button primary"
              disabled={importMutation.pending || !subject}
            >
              {importMutation.pending
                ? t("importing")
                : t("importMember")}
            </button>
          </div>
        </form>
      )}
    </Dialog>
  );
}
