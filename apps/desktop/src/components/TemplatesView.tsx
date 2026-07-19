import { useCallback, useEffect, useState } from "react";
import { api, isApiError } from "../api";
import type {
  DetectionReport,
  Project,
  StackPreference,
  Template,
  TemplateApplyOutcome,
} from "../types";

// Project templates and local stack detection. Detection is deterministic
// rules over static repository files plus the user's stored confirm/dismiss
// decisions — not machine learning — and nothing is executed or uploaded.
export function TemplatesView() {
  const [templates, setTemplates] = useState<Template[]>([]);
  const [selected, setSelected] = useState<Template | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  // Apply form.
  const [applyProject, setApplyProject] = useState("");
  const [exampleDir, setExampleDir] = useState("");
  const [applyOutcome, setApplyOutcome] = useState<TemplateApplyOutcome | null>(null);

  // Detection.
  const [detectProject, setDetectProject] = useState("");
  const [detectRepo, setDetectRepo] = useState("");
  const [reports, setReports] = useState<DetectionReport[]>([]);
  const [showDismissed, setShowDismissed] = useState(false);

  // Preferences.
  const [prefs, setPrefs] = useState<StackPreference[]>([]);

  const reload = useCallback(async () => {
    try {
      const [t, p, pr] = await Promise.all([
        api.templateList(),
        api.projectList(false),
        api.stackPrefs(),
      ]);
      setTemplates(t);
      setProjects(p);
      setPrefs(pr);
      setError("");
    } catch (err) {
      if (isApiError(err)) setError(err.message);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await action();
    } catch (err) {
      if (isApiError(err)) setError(err.message);
      else setError(String(err));
    } finally {
      setBusy(false);
    }
  };

  const detect = () =>
    run(async () => {
      const res = await api.stackDetect(
        detectProject === "" ? null : detectProject,
        detectRepo.trim() === "" ? null : detectRepo.trim(),
      );
      setReports(res);
      if (res.length === 0) setNotice("No repositories to inspect.");
    });

  const decide = (repo: string, templateId: string, decision: "confirmed" | "dismissed") =>
    run(async () => {
      await api.stackDecide(repo, templateId, decision);
      setNotice(
        `${decision === "confirmed" ? "Confirmed" : "Dismissed"} '${templateId}' — remembered locally; manage under Learned decisions.`,
      );
      const res = await api.stackDetect(
        detectProject === "" ? null : detectProject,
        detectRepo.trim() === "" ? null : detectRepo.trim(),
      );
      setReports(res);
      setPrefs(await api.stackPrefs());
    });

  return (
    <section>
      <h1>Templates</h1>
      <p className="muted">
        Templates seed a project with the right environments, variable names, and
        credential-separation guidance. They never contain values, and applying one never
        creates credentials — the follow-up commands do, explicitly.
      </p>
      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}

      <table>
        <thead>
          <tr>
            <th>Template</th>
            <th>Providers</th>
            <th>Secret vars</th>
            <th>Description</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {templates.map((t) => (
            <tr key={t.id}>
              <td>{t.name}</td>
              <td>{t.providers.join(", ")}</td>
              <td>{t.env.filter((v) => v.secret).length}</td>
              <td>{t.description}</td>
              <td>
                <button onClick={() => setSelected(selected?.id === t.id ? null : t)}>
                  {selected?.id === t.id ? "Close" : "Details / apply"}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {selected && (
        <div className="warnbox" style={{ background: "#f6f8f6", borderColor: "#9a9" }}>
          <h3>
            {selected.name} <span className="muted">({selected.id})</span>
          </h3>
          <p>{selected.description}</p>
          <ul>
            {selected.env.map((v) => (
              <li key={v.name}>
                <code>{v.name}</code> {v.secret ? "(secret)" : "(not secret)"} — {v.description}
              </li>
            ))}
          </ul>
          {selected.credential_separation && (
            <p>
              <strong>Credential separation:</strong> {selected.credential_separation}
            </p>
          )}
          {selected.permission_guidance && (
            <p>
              <strong>Permissions:</strong> {selected.permission_guidance}
            </p>
          )}
          {selected.rotation_guidance && (
            <p>
              <strong>Rotation:</strong> {selected.rotation_guidance}
            </p>
          )}
          <div className="stack">
            <label className="field">
              Project name (created if missing)
              <input value={applyProject} onChange={(e) => setApplyProject(e.target.value)} />
            </label>
            <label className="field">
              Write .env.example into directory (optional; names only)
              <input
                value={exampleDir}
                onChange={(e) => setExampleDir(e.target.value)}
                placeholder="/path/to/repo"
              />
            </label>
            <button
              disabled={busy || !applyProject.trim()}
              onClick={() =>
                void run(async () => {
                  const outcome = await api.templateApply(
                    selected.id,
                    applyProject.trim(),
                    exampleDir.trim() === "" ? null : exampleDir.trim(),
                  );
                  setApplyOutcome(outcome);
                  setNotice(
                    `Applied '${outcome.template.id}' to project '${outcome.project.name}'.`,
                  );
                  await reload();
                })
              }
            >
              Apply template
            </button>
          </div>
          {applyOutcome && applyOutcome.template.id === selected.id && (
            <div>
              {applyOutcome.example_path && <p>Wrote {applyOutcome.example_path}.</p>}
              {applyOutcome.next_steps.length > 0 && (
                <>
                  <p>
                    Next steps — credentials are only added by these explicit commands (each
                    prompts for its secret):
                  </p>
                  <pre>{applyOutcome.next_steps.join("\n")}</pre>
                </>
              )}
            </div>
          )}
        </div>
      )}

      <h2>Detect stack</h2>
      <p className="muted">
        Reads dependency manifests, lockfiles, framework config, and .env variable NAMES from a
        repository — values are never read into results, nothing is executed, nothing is
        uploaded. The evidence behind every suggestion is shown.
      </p>
      <div className="stack">
        <label className="field">
          Project (its registered repositories)
          <select value={detectProject} onChange={(e) => setDetectProject(e.target.value)}>
            <option value="">—</option>
            {projects.map((p) => (
              <option key={p.id} value={p.name}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          Or a repository directory
          <input
            value={detectRepo}
            onChange={(e) => setDetectRepo(e.target.value)}
            placeholder="/path/to/repo"
          />
        </label>
        <button
          disabled={busy || (detectProject === "" && detectRepo.trim() === "")}
          onClick={() => void detect()}
        >
          Detect
        </button>
        <label>
          <input
            type="checkbox"
            checked={showDismissed}
            onChange={(e) => setShowDismissed(e.target.checked)}
          />{" "}
          Show dismissed suggestions
        </label>
      </div>

      {reports.map((r) => (
        <div
          key={r.repo_path}
          className="warnbox"
          style={{ background: "#f7f7fb", borderColor: "#99b" }}
        >
          <h3 className="mono">{r.repo_path}</h3>
          {r.signals.length === 0 && <p>No stack signals found.</p>}
          {r.signals.length > 0 && (
            <>
              <p>
                <strong>Evidence:</strong>
              </p>
              <ul>
                {r.signals.map((s, i) => (
                  <li key={i}>
                    [{s.confidence}] <code>{s.file}</code>: {s.evidence}
                  </li>
                ))}
              </ul>
              <p>
                <strong>Suggestions</strong> (deterministic rules + your stored decisions — not
                ML):
              </p>
              <ul>
                {r.suggestions
                  .filter((s) => showDismissed || s.prior_decision !== "dismissed")
                  .map((s) => (
                    <li key={s.template_id}>
                      <strong>{s.template_id}</strong> [{s.confidence}]
                      {s.prior_decision === "confirmed" && " — you confirmed this earlier"}
                      {s.prior_decision === "dismissed" && " — you dismissed this earlier"}
                      <ul>
                        {s.evidence.map((e, i) => (
                          <li key={i} className="muted">
                            {e}
                          </li>
                        ))}
                      </ul>
                      <button
                        disabled={busy}
                        onClick={() => void decide(r.repo_path, s.template_id, "confirmed")}
                      >
                        Confirm
                      </button>{" "}
                      <button
                        disabled={busy}
                        onClick={() => void decide(r.repo_path, s.template_id, "dismissed")}
                      >
                        Dismiss
                      </button>
                    </li>
                  ))}
              </ul>
            </>
          )}
        </div>
      ))}

      <h2>Learned decisions</h2>
      <p className="muted">
        The complete locally stored detection history — nothing else is learned or kept.
      </p>
      {prefs.length === 0 && <p>No stored decisions.</p>}
      {prefs.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Repository</th>
              <th>Template</th>
              <th>Decision</th>
              <th>At</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {prefs.map((p) => (
              <tr key={`${p.repo_path}/${p.template_id}`}>
                <td className="mono">{p.repo_path}</td>
                <td>{p.template_id}</td>
                <td>{p.decision}</td>
                <td>{p.decided_at}</td>
                <td>
                  <button
                    disabled={busy}
                    onClick={() =>
                      void run(async () => {
                        await api.stackPrefsReset(p.repo_path);
                        setPrefs(await api.stackPrefs());
                        setNotice(`Deleted decisions for ${p.repo_path}.`);
                      })
                    }
                  >
                    Delete repo decisions
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {prefs.length > 0 && (
        <button
          disabled={busy}
          onClick={() =>
            void run(async () => {
              const n = await api.stackPrefsReset(null);
              setPrefs(await api.stackPrefs());
              setNotice(`Deleted all ${n} stored decision(s).`);
            })
          }
        >
          Delete ALL learned stack data
        </button>
      )}
    </section>
  );
}
