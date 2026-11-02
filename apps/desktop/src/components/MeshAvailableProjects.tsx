// "Available from your devices" on the Devices page (Tethra Mesh, Increment
// 10; DESIGN §D11, MESH-SI-13): projects another device shared that no local
// project here is bound to, each with "Bind to…" (an existing local project,
// or a new one created by name).
//
// Binding is never automatic: not by name, not by id, not on render. The
// list only reads `mesh_projects_list` (a background read, safe on the
// Devices poll); local projects are read only when the bind dialog opens.
// No analytics (MESH-SI-14).

import { useCallback, useEffect, useId, useRef, useState } from "react";
import { api } from "../api";
import type { MeshDeviceSummary, MeshProjectRow, Project } from "../types";
import { meshDeviceLabel, meshErrText, shortId } from "./MeshCommon";

function BindDialog(props: {
  target: MeshProjectRow;
  /** Local project id -> the shared project it is already bound to (core's rows). */
  boundTo: Map<string, string>;
  onBound: (notice: string) => void;
  onClose: () => void;
}) {
  const titleId = useId();
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [mode, setMode] = useState<"existing" | "new">("existing");
  const [choice, setChoice] = useState("");
  // Pre-filled for convenience only; nothing happens until "Bind".
  const [newName, setNewName] = useState(props.target.name);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let live = true;
    api
      .projectList(false)
      .then((p) => {
        if (!live) return;
        setProjects(p);
        if (p.length === 0) setMode("new");
      })
      .catch((e) => live && setError(meshErrText(e)));
    return () => {
      live = false;
    };
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    const meshId = props.target.mesh_project_id;
    try {
      if (mode === "existing") {
        const local = projects?.find((p) => p.id === choice);
        if (!local) return;
        await api.meshProjectBind(meshId, local.id);
        props.onBound(
          `Bound ${props.target.name} to ${local.name}. This device publishes its gateway ` +
            "usage for it from its next round.",
        );
      } else {
        // The same project creation the project form uses, name only.
        const created = await api.projectCreate({
          name: newName.trim(),
          description: "",
          notes: "",
          environments: [],
          repoPaths: [],
        });
        try {
          await api.meshProjectBind(meshId, created.id);
        } catch (bindErr) {
          setError(
            `Created the project ${created.name}, but binding it failed: ` +
              `${meshErrText(bindErr)}. Bind it from this list again.`,
          );
          return;
        }
        props.onBound(
          `Created ${created.name} and bound ${props.target.name} to it. This device publishes ` +
            "its gateway usage for it from its next round.",
        );
      }
    } catch (err) {
      setError(meshErrText(err));
    } finally {
      setBusy(false);
    }
  };

  const ready = mode === "existing" ? choice !== "" : newName.trim() !== "";

  return (
    <dialog open aria-labelledby={titleId}>
      <h2 id={titleId}>Bind {props.target.name} to a project on this device</h2>
      <p>
        This device then publishes its gateway usage for the project you choose to the shared
        project: daily counters (requests, tokens, estimated cost), never individual requests,
        request content, routes or credentials. Only this device is affected.
      </p>
      <form className="stack" onSubmit={(e) => void submit(e)}>
        <fieldset style={{ border: 0, padding: 0, margin: 0 }} className="stack">
          <legend className="muted">Bind to</legend>
          <label>
            <input
              type="radio"
              name="bind-mode"
              checked={mode === "existing"}
              disabled={projects !== null && projects.length === 0}
              onChange={() => setMode("existing")}
            />{" "}
            An existing project
          </label>
          {mode === "existing" && (
            <label className="field">
              Project
              <select value={choice} onChange={(e) => setChoice(e.target.value)}>
                <option value="">{projects === null ? "Loading…" : "Choose a project…"}</option>
                {(projects ?? []).map((p) => {
                  const bound = props.boundTo.get(p.id);
                  return (
                    <option key={p.id} value={p.id} disabled={bound !== undefined}>
                      {p.name}
                      {bound !== undefined ? ` (already bound to ${bound})` : ""}
                    </option>
                  );
                })}
              </select>
            </label>
          )}
          <label>
            <input
              type="radio"
              name="bind-mode"
              checked={mode === "new"}
              onChange={() => setMode("new")}
            />{" "}
            Create a new project
          </label>
          {mode === "new" && (
            <label className="field">
              New project name
              <input value={newName} onChange={(e) => setNewName(e.target.value)} required />
            </label>
          )}
        </fieldset>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button type="submit" disabled={busy || !ready}>
            {busy ? "Working…" : "Bind"}
          </button>
          <button type="button" onClick={props.onClose}>
            Cancel
          </button>
        </div>
      </form>
    </dialog>
  );
}

export function MeshAvailableProjects(props: {
  refreshKey: number;
  /** The roster from `mesh_status`, to name publishing devices. */
  devices: MeshDeviceSummary[];
  onChanged?: () => void;
}) {
  const titleId = useId();
  const [rows, setRows] = useState<MeshProjectRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [binding, setBinding] = useState<MeshProjectRow | null>(null);

  const seq = useRef(0);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const reload = useCallback(async () => {
    const mine = ++seq.current;
    try {
      const list = await api.meshProjectsList();
      if (!mounted.current || mine !== seq.current) return;
      setRows(list);
      setError(null);
    } catch (e) {
      if (!mounted.current || mine !== seq.current) return;
      setError(meshErrText(e));
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload, props.refreshKey]);

  // Available here: not bound on this device, not archived, not merged
  // (all three are core's fields).
  const available = (rows ?? []).filter(
    (r) => r.bound_local_project === null && !r.archived && r.merged_into === null,
  );
  const boundTo = new Map<string, string>();
  for (const r of rows ?? []) {
    if (r.bound_local_project !== null) boundTo.set(r.bound_local_project, r.name);
  }
  const deviceLabel = (id: string) =>
    meshDeviceLabel(props.devices.find((d) => d.device_id === id)?.name ?? null, id);

  return (
    <section className="card stack" aria-labelledby={titleId}>
      <h2 id={titleId}>Available from your devices</h2>
      <p className="muted" style={{ margin: 0 }}>
        Projects your other devices shared that no project on this device is bound to. Nothing
        binds by itself: bind one to a project here and this device publishes its gateway usage
        for it.
      </p>
      {notice && <p className="notice">{notice}</p>}
      {error && (
        <p className="error" role="alert">
          Could not read the shared projects: {error}
        </p>
      )}
      {rows === null && !error && <p className="muted">Loading…</p>}
      {rows !== null && available.length === 0 && (
        <p className="muted">
          None right now. A project another device shares appears here after this device&apos;s
          next exchange with it.
        </p>
      )}
      {available.length > 0 && (
        <div style={{ overflowX: "auto" }}>
          <table>
            <thead>
              <tr>
                <th scope="col">Shared project</th>
                <th scope="col">Id</th>
                <th scope="col">Published usage</th>
                <th scope="col">
                  <span className="muted">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {available.map((r) => (
                <tr key={r.mesh_project_id}>
                  <td>{r.name}</td>
                  <td>
                    <code>{shortId(r.mesh_project_id)}</code>
                  </td>
                  <td>
                    {r.publishing_devices.length === 0 ? (
                      <span className="muted">no device yet</span>
                    ) : (
                      r.publishing_devices.map(deviceLabel).join(", ")
                    )}
                  </td>
                  <td>
                    <button
                      type="button"
                      aria-label={`Bind ${r.name} (${shortId(r.mesh_project_id)}) to a project`}
                      onClick={() => {
                        setNotice(null);
                        setBinding(r);
                      }}
                    >
                      Bind to…
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {binding && (
        <BindDialog
          target={binding}
          boundTo={boundTo}
          onBound={(text) => {
            setBinding(null);
            setNotice(text);
            void reload();
            props.onChanged?.();
          }}
          onClose={() => setBinding(null)}
        />
      )}
    </section>
  );
}
