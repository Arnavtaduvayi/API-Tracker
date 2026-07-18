import { useEffect, useState } from "react";
import { api, isApiError } from "../api";
import { ENVIRONMENTS, type Environment } from "../types";

export function ProjectForm(props: {
  editIdent?: string;
  onDone: (ident: string | null) => void;
}) {
  const editing = props.editIdent !== undefined;
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [notes, setNotes] = useState("");
  const [environments, setEnvironments] = useState<Environment[]>([]);
  const [repoPaths, setRepoPaths] = useState<string[]>([]);
  const [newRepo, setNewRepo] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(!editing);

  useEffect(() => {
    if (props.editIdent) {
      api
        .projectGet(props.editIdent)
        .then((p) => {
          setName(p.name);
          setDescription(p.description);
          setNotes(p.notes);
          setEnvironments(p.environments);
          setRepoPaths(p.repo_paths);
          setLoaded(true);
        })
        .catch((e) => setError(isApiError(e) ? e.message : String(e)));
    }
  }, [props.editIdent]);

  const toggleEnv = (env: Environment) => {
    setEnvironments((current) =>
      current.includes(env) ? current.filter((e) => e !== env) : [...current, env],
    );
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const args = { name, description, notes, environments, repoPaths };
      const project = props.editIdent
        ? await api.projectUpdate(props.editIdent, args)
        : await api.projectCreate(args);
      props.onDone(project.id);
    } catch (err) {
      setError(isApiError(err) ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  if (!loaded) return <p>Loading…</p>;

  return (
    <div>
      <h1>{editing ? "Edit project" : "New project"}</h1>
      <form className="stack" onSubmit={(e) => void submit(e)}>
        <label className="field">
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} required autoFocus />
        </label>
        <label className="field">
          Description
          <input value={description} onChange={(e) => setDescription(e.target.value)} />
        </label>
        <fieldset>
          <legend>Environment classifications</legend>
          {ENVIRONMENTS.map((env) => (
            <label key={env} style={{ marginRight: "0.8rem" }}>
              <input
                type="checkbox"
                checked={environments.includes(env)}
                onChange={() => toggleEnv(env)}
              />{" "}
              {env}
            </label>
          ))}
        </fieldset>
        <fieldset>
          <legend>Local repository paths</legend>
          {repoPaths.map((repo) => (
            <div key={repo}>
              <span className="mono">{repo}</span>{" "}
              <button
                type="button"
                className="link danger"
                onClick={() => setRepoPaths((r) => r.filter((x) => x !== repo))}
              >
                remove
              </button>
            </div>
          ))}
          <div style={{ display: "flex", gap: "0.4rem", marginTop: "0.3rem" }}>
            <input
              placeholder="/path/to/repository"
              value={newRepo}
              onChange={(e) => setNewRepo(e.target.value)}
              style={{ flex: 1 }}
            />
            <button
              type="button"
              onClick={() => {
                const trimmed = newRepo.trim();
                if (trimmed && !repoPaths.includes(trimmed)) {
                  setRepoPaths((r) => [...r, trimmed]);
                }
                setNewRepo("");
              }}
            >
              Add path
            </button>
          </div>
        </fieldset>
        <label className="field">
          Notes (never encrypted; do not put secrets here)
          <textarea rows={3} value={notes} onChange={(e) => setNotes(e.target.value)} />
        </label>
        {error && <p className="error">{error}</p>}
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button type="submit" disabled={busy}>
            {busy ? "Saving…" : editing ? "Save changes" : "Create project"}
          </button>
          <button type="button" onClick={() => props.onDone(props.editIdent ?? null)}>
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}
