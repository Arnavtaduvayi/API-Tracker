// .env governance: discover environment files across a project's registered
// repositories, preview variables (masked — values never rendered), import
// them into the encrypted vault, keep .env.example in sync (names only),
// detect drift, and manage recorded plaintext exports. Export requires
// master-password reauthentication and explicit confirmation.

import { useCallback, useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type {
  CleanupResult,
  DriftFinding,
  EnvExampleProposal,
  EnvExport,
  EnvFileInfo,
  EnvImportOutcome,
  Project,
  VarPreview,
} from "../types";
import { driftSeverity, formatTimestamp } from "../utils";
import { ConfirmDialog } from "./ConfirmDialog";
import { ReauthDialog } from "./ReauthDialog";

type PendingConfirm = "import" | "write-example" | "cleanup-expired" | "cleanup-all";

function gitBadge(f: EnvFileInfo) {
  if (f.git_status === "tracked" && f.class === "values") {
    return <span className="badge bad">tracked — committed secrets risk</span>;
  }
  switch (f.git_status) {
    case "tracked":
      return <span className="badge ok">tracked</span>;
    case "ignored":
      return <span className="badge ok">ignored</span>;
    case "untracked":
      return <span className="badge warn">untracked</span>;
    default:
      return <span className="muted">not in a repo</span>;
  }
}

export function EnvView() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [project, setProject] = useState("");
  const [path, setPath] = useState("");
  const [files, setFiles] = useState<EnvFileInfo[] | null>(null);
  const [selected, setSelected] = useState<EnvFileInfo | null>(null);
  const [preview, setPreview] = useState<VarPreview[] | null>(null);
  const [checked, setChecked] = useState<Record<string, boolean>>({});
  const [outcomes, setOutcomes] = useState<EnvImportOutcome[] | null>(null);
  const [example, setExample] = useState<EnvExampleProposal | null>(null);
  const [drift, setDrift] = useState<DriftFinding[] | null>(null);
  const [exports, setExports] = useState<EnvExport[]>([]);
  const [cleanupForce, setCleanupForce] = useState(false);
  const [cleanupResults, setCleanupResults] = useState<CleanupResult[] | null>(null);
  const [confirming, setConfirming] = useState<PendingConfirm | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Explicit export form (reauthentication-gated).
  const [showExport, setShowExport] = useState(false);
  const [exportPath, setExportPath] = useState("");
  const [exportVars, setExportVars] = useState("");
  const [exportOverwrite, setExportOverwrite] = useState(false);
  const [exportTtl, setExportTtl] = useState("");
  const [exportReauth, setExportReauth] = useState(false);

  const run = async (action: () => Promise<void>) => {
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      await action();
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const reloadExports = useCallback(async () => {
    try {
      setExports(await api.envExportsList());
    } catch (e) {
      setError(isApiError(e) ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    api
      .projectList(false)
      .then((p) => {
        setProjects(p);
        if (p.length > 0) setProject(p[0].id);
      })
      .catch((e) => setError(isApiError(e) ? e.message : String(e)));
    void reloadExports();
  }, [reloadExports]);

  const discover = () =>
    run(async () => {
      if (!project && !path.trim()) {
        setError("Choose a project or enter a directory path to search.");
        return;
      }
      setSelected(null);
      setPreview(null);
      setExample(null);
      setOutcomes(null);
      setFiles(await api.envDiscover(project || null, path.trim() || null));
    });

  const openFile = (f: EnvFileInfo) =>
    run(async () => {
      setSelected(f);
      setPreview(null);
      setExample(null);
      setOutcomes(null);
      setChecked({});
      if (f.class === "values") {
        setExample(await api.envExamplePreview(f.path));
        if (project) {
          const rows = await api.envPreview(project, f.path);
          setPreview(rows);
          const initial: Record<string, boolean> = {};
          for (const row of rows) {
            initial[row.key] = row.looks_secret && !row.is_placeholder;
          }
          setChecked(initial);
        }
      }
    });

  const selectedKeys = preview ? preview.filter((v) => checked[v.key]).map((v) => v.key) : [];
  const projectName = projects.find((p) => p.id === project)?.name ?? project;

  const doImport = () =>
    run(async () => {
      if (!selected || !project) return;
      const result = await api.envImport(project, selected.path, selectedKeys);
      setOutcomes(result);
      const imported = result.filter(
        (o) => o.action === "imported" || o.action === "mapped_existing",
      ).length;
      setNotice(`${imported} variable(s) imported or mapped. The file was not modified.`);
      // Refresh the preview so vault matches and mappings show up.
      setPreview(await api.envPreview(project, selected.path));
    });

  const writeExample = () =>
    run(async () => {
      if (!selected || !example) return;
      await api.envExampleWrite(example.example_path, example.proposed);
      setNotice(`Wrote ${example.example_path} (names only, never values).`);
      setExample(await api.envExamplePreview(selected.path));
    });

  const checkDrift = () =>
    run(async () => {
      if (!project) {
        setError("Choose a project to check drift.");
        return;
      }
      setDrift(await api.envDrift(project));
    });

  const cleanup = (all: boolean) =>
    run(async () => {
      const results = await api.envCleanup(all, cleanupForce);
      setCleanupResults(results);
      const removed = results.filter((r) => r.outcome === "removed").length;
      setNotice(`${removed} exported file(s) removed.`);
      await reloadExports();
    });

  const confirmDialog = () => {
    switch (confirming) {
      case "import":
        return (
          <ConfirmDialog
            title="Import variables into the vault"
            body={`Import ${selectedKeys.length} variable(s) into project "${projectName}"? Values are stored encrypted and mapped for injection. The file itself is not modified.`}
            confirmLabel="Import"
            onConfirm={() => {
              setConfirming(null);
              void doImport();
            }}
            onCancel={() => setConfirming(null)}
          />
        );
      case "write-example":
        return (
          <ConfirmDialog
            title="Write .env.example"
            body={`Write ${example?.example_path ?? ""}? It lists variable names only — never values — and preserves existing entries.`}
            confirmLabel="Write .env.example"
            onConfirm={() => {
              setConfirming(null);
              void writeExample();
            }}
            onCancel={() => setConfirming(null)}
          />
        );
      case "cleanup-expired":
        return (
          <ConfirmDialog
            title="Clean up expired exports"
            body={
              "Delete exported .env files whose temporary lifetime has passed?" +
              (cleanupForce
                ? " Force is set: files changed since export are deleted too."
                : " Files changed since export are kept unless force is checked.")
            }
            confirmLabel="Clean up expired"
            danger
            onConfirm={() => {
              setConfirming(null);
              void cleanup(false);
            }}
            onCancel={() => setConfirming(null)}
          />
        );
      case "cleanup-all":
        return (
          <ConfirmDialog
            title="Remove every recorded export"
            body={
              "Delete EVERY exported .env file recorded by API Tracker, expired or not?" +
              (cleanupForce
                ? " Force is set: files changed since export are deleted too."
                : " Files changed since export are kept unless force is checked.")
            }
            confirmLabel="Clean up all"
            danger
            onConfirm={() => {
              setConfirming(null);
              void cleanup(true);
            }}
            onCancel={() => setConfirming(null)}
          />
        );
      default:
        return null;
    }
  };

  return (
    <div>
      <h1>Env files</h1>
      <p className="muted">
        Everything here runs locally. Previews and diffs show masked values only; plaintext is
        written to disk only through the explicit, password-confirmed export below.
      </p>

      <h2>Discover</h2>
      <div className="stack" style={{ maxWidth: "44rem" }}>
        <label className="field">
          Project (its registered repositories are searched; also the import target)
          <select value={project} onChange={(e) => setProject(e.target.value)}>
            <option value="">— none —</option>
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          Extra directory to search (optional)
          <input
            className="mono"
            placeholder="/path/to/repo"
            value={path}
            onChange={(e) => setPath(e.target.value)}
          />
        </label>
        <div>
          <button onClick={() => void discover()} disabled={busy}>
            {busy ? "Working…" : "Discover .env files"}
          </button>
        </div>
      </div>

      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}

      {files && (
        <div style={{ marginTop: "1rem" }}>
          {files.length === 0 ? (
            <p>No .env files found.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>File</th>
                  <th>Class</th>
                  <th>Environment</th>
                  <th>Git</th>
                  <th>Vars</th>
                  <th>Problems</th>
                </tr>
              </thead>
              <tbody>
                {files.map((f) => (
                  <tr key={f.path}>
                    <td>
                      <button className="link mono" onClick={() => void openFile(f)}>
                        {f.rel_path}
                      </button>
                    </td>
                    <td>{f.class}</td>
                    <td>{f.environment ?? "—"}</td>
                    <td>
                      {gitBadge(f)}
                      {f.in_git_history && f.class === "values" && (
                        <div className="muted">
                          in Git history — deleting the file does not remove past commits
                        </div>
                      )}
                    </td>
                    <td>{f.entry_count}</td>
                    <td>{f.problems.length > 0 ? f.problems.length : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {selected && (
        <div style={{ marginTop: "1rem" }}>
          <h2 className="mono">{selected.rel_path}</h2>
          {selected.class === "template" ? (
            <p className="muted">
              Template file (variable names only, by convention) — there is nothing to import.
            </p>
          ) : !project ? (
            <p className="muted">Choose a project above to preview and import this file.</p>
          ) : (
            preview && (
              <>
                <table>
                  <thead>
                    <tr>
                      <th>Import</th>
                      <th>Variable</th>
                      <th>Value (masked)</th>
                      <th>Provider</th>
                      <th>Secret?</th>
                      <th>Placeholder?</th>
                      <th>In vault</th>
                      <th>Mapped to</th>
                    </tr>
                  </thead>
                  <tbody>
                    {preview.map((v) => (
                      <tr key={`${v.key}:${v.line}`}>
                        <td>
                          <input
                            type="checkbox"
                            aria-label={`import ${v.key}`}
                            checked={checked[v.key] ?? false}
                            onChange={(e) =>
                              setChecked((c) => ({ ...c, [v.key]: e.target.checked }))
                            }
                          />
                        </td>
                        <td className="mono">{v.key}</td>
                        <td className="mono">{v.masked}</td>
                        <td>{v.provider ?? "—"}</td>
                        <td>{v.looks_secret ? "yes" : "—"}</td>
                        <td>{v.is_placeholder ? "yes" : "—"}</td>
                        <td>{v.vault_credential ?? "—"}</td>
                        <td>{v.mapped_credential ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <div style={{ display: "flex", gap: "0.5rem" }}>
                  <button
                    onClick={() =>
                      setChecked(
                        Object.fromEntries(
                          preview.map((v) => [v.key, v.looks_secret && !v.is_placeholder]),
                        ),
                      )
                    }
                  >
                    Select all secrets
                  </button>
                  <button
                    onClick={() => setConfirming("import")}
                    disabled={busy || selectedKeys.length === 0}
                  >
                    Import {selectedKeys.length} variable(s)…
                  </button>
                </div>
              </>
            )
          )}

          {outcomes && (
            <div style={{ marginTop: "0.5rem" }}>
              <h3>Import outcome</h3>
              <table>
                <thead>
                  <tr>
                    <th>Variable</th>
                    <th>Action</th>
                    <th>Credential</th>
                    <th>Note</th>
                  </tr>
                </thead>
                <tbody>
                  {outcomes.map((o) => (
                    <tr key={o.key}>
                      <td className="mono">{o.key}</td>
                      <td>{o.action}</td>
                      <td>{o.credential ?? "—"}</td>
                      <td>{o.note}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {selected.class === "values" && example && (
            <div style={{ marginTop: "0.5rem" }}>
              <h3>.env.example</h3>
              {example.changed ? (
                <>
                  <p className="muted">
                    Proposed update to <span className="mono">{example.example_path}</span>{" "}
                    (names only; secret values in the diff are masked):
                  </p>
                  <pre
                    className="mono"
                    style={{
                      border: "1px solid #ddd",
                      padding: "0.5rem",
                      overflowX: "auto",
                    }}
                  >
                    {example.diff}
                  </pre>
                  <button onClick={() => setConfirming("write-example")} disabled={busy}>
                    Write .env.example…
                  </button>
                </>
              ) : (
                <p className="muted">{example.example_path} is already up to date.</p>
              )}
            </div>
          )}
        </div>
      )}

      <h2 style={{ marginTop: "1.5rem" }}>Drift</h2>
      <p className="muted">
        Compares this project&apos;s .env files against the vault and its injection mappings.
      </p>
      <button onClick={() => void checkDrift()} disabled={busy || !project}>
        {busy ? "Working…" : "Check drift"}
      </button>
      {drift &&
        (drift.length === 0 ? (
          <p className="notice">No drift detected.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Kind</th>
                <th>File</th>
                <th>Variable</th>
                <th>Credential</th>
                <th>Detail</th>
                <th>Recommendation</th>
              </tr>
            </thead>
            <tbody>
              {drift.map((d, i) => {
                const severity = driftSeverity(d.kind);
                return (
                  <tr key={i}>
                    <td>
                      <span
                        className={`badge ${
                          severity === "high" ? "bad" : severity === "medium" ? "warn" : "ok"
                        }`}
                      >
                        {severity}
                      </span>
                    </td>
                    <td>{d.kind.replaceAll("_", " ")}</td>
                    <td className="mono">{d.file || "—"}</td>
                    <td className="mono">{d.key}</td>
                    <td>{d.credential ?? "—"}</td>
                    <td>{d.detail}</td>
                    <td>{d.recommendation}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ))}

      <h2 style={{ marginTop: "1.5rem" }}>Exports</h2>
      <p className="muted">
        Plaintext .env files previously written by API Tracker. Prefer running projects through
        injection (no file); when a file is unavoidable, export it with a lifetime and clean it
        up here.
      </p>
      {exports.length === 0 ? (
        <p>No live exports.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Path</th>
              <th>Variables</th>
              <th>Created</th>
              <th>Expires</th>
            </tr>
          </thead>
          <tbody>
            {exports.map((e) => (
              <tr key={e.id}>
                <td className="mono">{e.path}</td>
                <td className="mono">{e.var_names}</td>
                <td>{formatTimestamp(e.created_at)}</td>
                <td>{e.expires_at ? formatTimestamp(e.expires_at) : "never (persistent)"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", flexWrap: "wrap" }}>
        <button
          onClick={() => setConfirming("cleanup-expired")}
          disabled={busy || exports.length === 0}
        >
          Clean up expired…
        </button>
        <button
          className="danger"
          onClick={() => setConfirming("cleanup-all")}
          disabled={busy || exports.length === 0}
        >
          Clean up all…
        </button>
        <label>
          <input
            type="checkbox"
            checked={cleanupForce}
            onChange={(e) => setCleanupForce(e.target.checked)}
          />{" "}
          force: also delete files whose content changed since export (otherwise they are kept,
          since edits may be yours)
        </label>
        <button onClick={() => setShowExport((v) => !v)} disabled={!project}>
          Export .env…
        </button>
      </div>
      {cleanupResults && cleanupResults.length > 0 && (
        <ul className="muted">
          {cleanupResults.map((r) => (
            <li key={r.export_id}>
              <span className="mono">{r.path}</span>: {r.outcome.replaceAll("_", " ")}
            </li>
          ))}
        </ul>
      )}

      {showExport && (
        <form
          className="stack"
          style={{ maxWidth: "32rem" }}
          onSubmit={(e) => {
            e.preventDefault();
            setError(null);
            if (!exportPath.trim()) {
              setError("Enter a target path for the export.");
              return;
            }
            setExportReauth(true);
          }}
        >
          <h3>Export mapped credentials to a plaintext .env file</h3>
          <p className="muted">
            The file will contain PLAINTEXT secrets. It is written atomically with owner-only
            permissions and refused when the target is tracked by Git.
          </p>
          <label className="field">
            Target path
            <input
              className="mono"
              placeholder="/path/to/repo/.env"
              value={exportPath}
              onChange={(e) => setExportPath(e.target.value)}
              required
            />
          </label>
          <label className="field">
            Variables (comma-separated; empty = every configured mapping)
            <input
              className="mono"
              value={exportVars}
              onChange={(e) => setExportVars(e.target.value)}
            />
          </label>
          <label className="field">
            Temporary lifetime in minutes (empty = persists until you delete it)
            <input
              type="number"
              min={1}
              value={exportTtl}
              onChange={(e) => setExportTtl(e.target.value)}
            />
          </label>
          <label>
            <input
              type="checkbox"
              checked={exportOverwrite}
              onChange={(e) => setExportOverwrite(e.target.checked)}
            />{" "}
            overwrite the file if it already exists
          </label>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button type="submit" disabled={busy}>
              Export…
            </button>
            <button type="button" onClick={() => setShowExport(false)}>
              Cancel
            </button>
          </div>
        </form>
      )}

      {exportReauth && (
        <ReauthDialog
          title={`Write plaintext secrets to ${exportPath.trim()}`}
          actionLabel="Export"
          onConfirm={async (password) => {
            const vars = exportVars
              .split(",")
              .map((v) => v.trim())
              .filter((v) => v !== "");
            const ttl = exportTtl.trim() === "" ? null : Number(exportTtl);
            const report = await api.envExport({
              project,
              path: exportPath.trim(),
              vars: vars.length > 0 ? vars : null,
              password,
              overwrite: exportOverwrite,
              ttlMinutes: ttl,
            });
            setShowExport(false);
            setNotice(
              `Exported ${report.var_names.length} variable(s) to ${report.path}. ` +
                report.warnings.join(" "),
            );
            await reloadExports();
          }}
          onClose={() => setExportReauth(false)}
        />
      )}

      {confirmDialog()}
    </div>
  );
}
