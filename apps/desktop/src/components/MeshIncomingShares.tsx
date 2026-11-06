// "Credentials shared with this device" on the Devices page (Tethra Mesh,
// Increment 11; ADR 0033). Each share another device sealed to this one, with
// Import: choose a local project, confirm the master password, and core opens
// the share, checks every sealed field against the signed envelope, and
// stores the value re-encrypted under that project's key.
//
// Nothing imports by itself (MESH-SI-13): opening the list (and an import)
// first collects shares addressed to removed devices; the Devices poll is a
// background read that writes nothing; only the dialog's explicit Import
// stores a credential. A share from a device since removed is listed but
// cannot be imported. No value is
// ever rendered: an import shows the stored credential's masked form. No
// analytics (MESH-SI-14).

import { useCallback, useEffect, useId, useRef, useState } from "react";
import { api } from "../api";
import type { MeshShareRow, Project } from "../types";
import { ReauthDialog } from "./ReauthDialog";
import { meshDeviceLabel, meshErrText, scrubbed, shortId } from "./MeshCommon";

const ENVIRONMENTS = ["development", "test", "staging", "production"] as const;

function ImportDialog(props: {
  share: MeshShareRow;
  onImported: (notice: string) => void;
  onClose: () => void;
}) {
  const titleId = useId();
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [project, setProject] = useState("");
  const [replace, setReplace] = useState(false);
  const [environment, setEnvironment] = useState<string>("development");
  const [reauth, setReauth] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    api
      .projectList(false)
      .then((p) => live && setProjects(p))
      .catch((e) => live && setError(meshErrText(e)));
    return () => {
      live = false;
    };
  }, []);

  const s = props.share;
  const target = projects?.find((p) => p.id === project);

  if (reauth && target) {
    return (
      <ReauthDialog
        title={`Import ${s.credential_name}`}
        actionLabel="Import"
        body={
          `Store this credential from ${meshDeviceLabel(s.sharer_name, s.sharer)} in ` +
          `${target.name}${replace ? ", replacing the value of a credential with the same name" : ""}.`
        }
        onConfirm={async (password) => {
          try {
            const r = await api.meshCredentialImport(
              password,
              s.share_id,
              target.id,
              replace,
              environment,
            );
            props.onImported(
              `${r.replaced ? "Replaced" : "Imported"} ${r.credential.project_name}/` +
                `${r.credential.name} (${r.credential.masked_value}).` +
                (r.replaced ? " The previous value is kept as a version." : ""),
            );
          } catch (e) {
            throw scrubbed(e, [password]);
          }
        }}
        onClose={props.onClose}
      />
    );
  }

  return (
    <dialog open aria-labelledby={titleId}>
      <h2 id={titleId}>Import {s.credential_name}</h2>
      <p>
        Shared by {meshDeviceLabel(s.sharer_name, s.sharer)} ({s.provider}, value version v
        {s.value_version}). The value is stored in the project you choose, encrypted with that
        project&apos;s key. Revoking the share later does not remove it from this device.
      </p>
      <form
        className="stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (target) setReauth(true);
        }}
      >
        <label className="field">
          Project on this device
          <select value={project} onChange={(e) => setProject(e.target.value)}>
            <option value="">{projects === null ? "Loading…" : "Choose a project…"}</option>
            {(projects ?? []).map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
                {p.password_locked && !p.unlocked ? " (locked)" : ""}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          Environment (for a new credential)
          <select value={environment} onChange={(e) => setEnvironment(e.target.value)}>
            {ENVIRONMENTS.map((env) => (
              <option key={env} value={env}>
                {env}
              </option>
            ))}
          </select>
        </label>
        <label>
          <input
            type="checkbox"
            checked={replace}
            onChange={(e) => setReplace(e.target.checked)}
          />{" "}
          If the project already has a credential named {s.credential_name}, replace its value
          (the old value is kept as a version)
        </label>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button type="submit" disabled={!target}>
            Continue
          </button>
          <button type="button" onClick={props.onClose}>
            Cancel
          </button>
        </div>
      </form>
    </dialog>
  );
}

export function MeshIncomingShares(props: { refreshKey: number; onChanged?: () => void }) {
  const titleId = useId();
  const [rows, setRows] = useState<MeshShareRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [importing, setImporting] = useState<MeshShareRow | null>(null);

  const opened = useRef(false);
  const reload = useCallback(async (purge: boolean) => {
    try {
      const list = await api.meshSharesList(purge);
      setRows(list.incoming);
      setError(null);
    } catch (e) {
      setError(meshErrText(e));
    }
  }, []);

  useEffect(() => {
    // The first read on opening collects old shares; the poll only reads.
    const purge = !opened.current;
    opened.current = true;
    void reload(purge);
  }, [reload, props.refreshKey]);

  return (
    <section className="card stack" aria-labelledby={titleId}>
      <h2 id={titleId}>Credentials shared with this device</h2>
      <p className="muted" style={{ margin: 0 }}>
        Credentials your other devices sealed to this one. Nothing is imported by itself: import
        one into a project here with your master password.
      </p>
      {notice && (
        <p className="notice" role="status">
          {notice}
        </p>
      )}
      {error && (
        <p className="error" role="alert">
          Could not read the shared credentials: {error}
        </p>
      )}
      {rows === null && !error && <p className="muted">Loading…</p>}
      {rows !== null && rows.length === 0 && (
        <p className="muted">
          None. A credential another device shares with this one appears here after the next
          exchange.
        </p>
      )}
      {rows !== null && rows.length > 0 && (
        <div style={{ overflowX: "auto" }}>
          <table>
            <thead>
              <tr>
                <th scope="col">Credential</th>
                <th scope="col">Provider</th>
                <th scope="col">From</th>
                <th scope="col">Share</th>
                <th scope="col">State</th>
                <th scope="col">
                  <span className="muted">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.share_id}>
                  <td>{r.credential_name}</td>
                  <td>{r.provider}</td>
                  <td>{meshDeviceLabel(r.sharer_name, r.sharer)}</td>
                  <td>
                    <code>{shortId(r.share_id)}</code> v{r.value_version}
                  </td>
                  <td>
                    {r.revoked
                      ? "revoked"
                      : r.imported
                        ? `imported as ${r.imported.project_name}/${r.imported.credential_name}`
                        : !r.sharer_active
                          ? "from a removed device (cannot be imported)"
                          : "available"}
                  </td>
                  <td>
                    {!r.revoked && !r.imported && r.sharer_active && (
                      <button
                        type="button"
                        aria-label={`Import ${r.credential_name} from ${meshDeviceLabel(r.sharer_name, r.sharer)}`}
                        onClick={() => {
                          setNotice(null);
                          setImporting(r);
                        }}
                      >
                        Import into…
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {importing && (
        <ImportDialog
          share={importing}
          onImported={(text) => {
            setNotice(text);
            void reload(true);
            props.onChanged?.();
          }}
          onClose={() => setImporting(null)}
        />
      )}
    </section>
  );
}
