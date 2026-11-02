// The "Devices" panel on a project's page (Tethra Mesh, Increment 10; DESIGN
// §D11, MESH-SI-13). Not shared: an explicit "Share with my devices". Shared:
// the mesh project, which devices publish usage for it, Unbind, a small
// Manage area (rename, archive, merge), then the cross-device usage card and
// the spend-cap panel.
//
// Nothing here shares, binds or merges on its own: rendering only reads
// (`mesh_status`, `mesh_projects_list`); every change is one explicit click,
// and unbind, archive and merge ask first. No analytics (MESH-SI-14).

import { useCallback, useEffect, useId, useRef, useState } from "react";
import { api } from "../api";
import type { MeshProjectRow, MeshStatus } from "../types";
import { ConfirmDialog, PromptDialog } from "./ConfirmDialog";
import { CapsPanel } from "./CapsPanel";
import { MeshUsageCard } from "./MeshUsageCard";
import { meshDeviceLabel, meshErrText, shortId } from "./MeshCommon";

/** Exactly what sharing a project replicates; shown before the click. */
export const SHARE_EXPLANATION =
  "Sharing replicates this project's daily usage counters (requests, tokens, estimated cost) " +
  "to your paired devices, never individual requests, request content, routes or " +
  "credentials. Your other devices see it only after you bind it there to one of their own " +
  "projects.";

type Dialog =
  | { kind: "unbind" }
  | { kind: "rename" }
  | { kind: "archive" }
  | { kind: "merge"; other: MeshProjectRow };

export function MeshProjectPanel(props: {
  /** The local project's id (not its name). */
  projectId: string;
  projectName: string;
}) {
  const titleId = useId();
  const mergeId = useId();
  const [status, setStatus] = useState<MeshStatus | null>(null);
  const [rows, setRows] = useState<MeshProjectRow[] | null>(null);
  /** A failed read (status or list); cleared by the next good read. */
  const [error, setError] = useState<string | null>(null);
  /** A failed action; stays until the next action. */
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [mergeWith, setMergeWith] = useState("");
  /** Bumped after an action, so the usage card publishes and re-reads. */
  const [actionKey, setActionKey] = useState(0);

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
      const s = await api.meshStatus();
      if (!mounted.current || mine !== seq.current) return;
      setStatus(s);
      if (!s.initialized) return;
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
  }, [reload]);

  const act = async (fn: () => Promise<string>) => {
    setBusy(true);
    setActionError(null);
    setNotice(null);
    try {
      setNotice(await fn());
      setActionKey((k) => k + 1);
    } catch (e) {
      setActionError(meshErrText(e));
    } finally {
      setBusy(false);
    }
    await reload();
  };

  const titleRow = (
    <div style={{ display: "flex", alignItems: "baseline", gap: "0.75rem" }}>
      <h2 id={titleId} style={{ margin: 0 }}>
        Devices
      </h2>
      <span className="muted">Tethra Mesh</span>
    </div>
  );

  if (status !== null && !status.initialized) {
    return (
      <section className="card stack" aria-labelledby={titleId}>
        {titleRow}
        <p className="muted" style={{ margin: 0 }}>
          This device is not in a mesh. To see this project&apos;s usage across your devices,
          create or join one under Devices in the sidebar.
        </p>
      </section>
    );
  }

  // This device's binding for this local project, if any (core's field).
  const mine = rows?.find((r) => r.bound_local_project === props.projectId) ?? null;
  const selfId = status?.initialized ? status.device_id : null;
  const deviceName = (id: string): string => {
    const d = status?.initialized ? status.devices.find((x) => x.device_id === id) : undefined;
    return meshDeviceLabel(d?.name ?? null, id);
  };
  const nameOf = (id: string) =>
    rows?.find((r) => r.mesh_project_id === id)?.name ?? shortId(id);
  // Merge candidates: other shared projects that are not archived, not
  // merged, and not already one project with this one (core's `root`).
  const candidates =
    mine === null
      ? []
      : (rows ?? []).filter(
          (r) =>
            r.mesh_project_id !== mine.mesh_project_id &&
            r.root !== mine.root &&
            !r.archived &&
            r.merged_into === null,
        );

  return (
    <>
      <section
        className="card stack"
        aria-labelledby={titleId}
        data-testid="mesh-project-panel"
      >
        {titleRow}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        {actionError && (
          <p className="error" role="alert">
            {actionError}
          </p>
        )}
        {notice && <p className="notice">{notice}</p>}
        {(status === null || rows === null) && !error && <p className="muted">Loading…</p>}

        {rows !== null && mine === null && (
          <>
            <p style={{ margin: 0 }}>This project is not shared with your other devices.</p>
            <p className="muted" style={{ margin: 0 }}>
              {SHARE_EXPLANATION}
            </p>
            <div>
              <button
                type="button"
                className="primary"
                disabled={busy}
                onClick={() =>
                  void act(async () => {
                    const r = await api.meshProjectShare(props.projectId);
                    return (
                      `Shared as ${r.name} (${shortId(r.mesh_project_id)}). On another device, ` +
                      "bind it to a project there (Devices, Available from your devices)."
                    );
                  })
                }
              >
                Share with my devices
              </button>
            </div>
          </>
        )}

        {mine !== null && (
          <>
            <p style={{ margin: 0 }}>
              Shared as <strong>{mine.name}</strong>{" "}
              <code>{shortId(mine.mesh_project_id)}</code>{" "}
              {mine.archived && <span className="badge">archived</span>}
            </p>
            {mine.merged_into !== null && (
              <p className="muted" style={{ margin: 0 }}>
                Merged into {nameOf(mine.root)} ({shortId(mine.root)}): its usage and spend cap
                are counted there.
              </p>
            )}
            <p style={{ margin: 0 }}>
              {mine.publishing_devices.length === 0 ? (
                <span className="muted">No device has published usage for it yet.</span>
              ) : (
                <>
                  {mine.publishing_devices.length} device(s) published usage for it:{" "}
                  {mine.publishing_devices
                    .map((d) => deviceName(d) + (d === selfId ? " — this device" : ""))
                    .join(", ")}
                  .
                </>
              )}
            </p>
            <p className="muted" style={{ margin: 0 }}>
              This device publishes its gateway usage for {props.projectName} to it: daily
              counters only, never individual requests, content, routes or credentials.
            </p>
            <div>
              <button
                type="button"
                disabled={busy}
                onClick={() => setDialog({ kind: "unbind" })}
              >
                Unbind
              </button>
            </div>

            <details>
              <summary>Manage the shared project</summary>
              <div className="stack" style={{ marginTop: "0.5rem" }}>
                <p className="muted" style={{ margin: 0 }}>
                  Rename, archive and merge apply on every device.
                </p>
                <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => setDialog({ kind: "rename" })}
                  >
                    Rename
                  </button>
                  {!mine.archived && (
                    <button
                      type="button"
                      className="danger"
                      disabled={busy}
                      onClick={() => setDialog({ kind: "archive" })}
                    >
                      Archive shared project
                    </button>
                  )}
                </div>
                {candidates.length > 0 ? (
                  <form
                    style={{
                      display: "flex",
                      gap: "0.5rem",
                      alignItems: "flex-end",
                      flexWrap: "wrap",
                    }}
                    onSubmit={(e) => {
                      e.preventDefault();
                      const other = candidates.find((c) => c.mesh_project_id === mergeWith);
                      if (other) setDialog({ kind: "merge", other });
                    }}
                  >
                    <label className="field" htmlFor={mergeId}>
                      Merge with another shared project (the same real project)
                      <select
                        id={mergeId}
                        value={mergeWith}
                        onChange={(e) => setMergeWith(e.target.value)}
                      >
                        <option value="">Choose a shared project…</option>
                        {candidates.map((c) => (
                          <option key={c.mesh_project_id} value={c.mesh_project_id}>
                            {c.name} ({shortId(c.mesh_project_id)})
                          </option>
                        ))}
                      </select>
                    </label>
                    <button type="submit" disabled={busy || mergeWith === ""}>
                      Merge…
                    </button>
                  </form>
                ) : (
                  <p className="muted" style={{ margin: 0 }}>
                    No other shared project to merge with.
                  </p>
                )}
              </div>
            </details>
          </>
        )}
      </section>

      {mine !== null && (
        <>
          <MeshUsageCard meshProjectId={mine.mesh_project_id} refreshKey={actionKey} />
          <CapsPanel
            key={`caps-${actionKey}`}
            meshProjectId={mine.mesh_project_id}
            projects={rows ?? []}
            archived={mine.archived}
          />
        </>
      )}

      {dialog?.kind === "unbind" && mine !== null && (
        <ConfirmDialog
          title={`Unbind ${props.projectName}?`}
          body={
            `This device stops publishing new usage for ${props.projectName} to the shared ` +
            `project ${mine.name}. What it already published stays, and the shared project ` +
            "stays on your other devices. You can bind it again later from Devices."
          }
          confirmLabel="Unbind"
          danger
          onConfirm={() => {
            setDialog(null);
            void act(async () => {
              const removed = await api.meshProjectUnbind(props.projectId);
              return removed
                ? `Unbound. This device no longer publishes usage for ${props.projectName}.`
                : "This project was not bound on this device.";
            });
          }}
          onCancel={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "rename" && mine !== null && (
        <PromptDialog
          title={`Rename the shared project ${mine.name}`}
          body="The new name applies on every device. Your local project keeps its own name."
          placeholder={mine.name}
          confirmLabel="Rename"
          onConfirm={(name) => {
            setDialog(null);
            void act(async () => {
              await api.meshProjectRename(mine.mesh_project_id, name);
              return `Renamed the shared project to ${name.trim()}.`;
            });
          }}
          onCancel={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "archive" && mine !== null && (
        <ConfirmDialog
          title={`Archive the shared project ${mine.name}?`}
          body={
            "Archiving applies on every device. Its published usage stays readable, but no " +
            "device can bind it or create a spend cap on it any more, and Tethra has no way to " +
            "unarchive it. Your local project is not changed."
          }
          confirmLabel="Archive shared project"
          danger
          onConfirm={() => {
            setDialog(null);
            void act(async () => {
              await api.meshProjectArchive(mine.mesh_project_id);
              return `Archived the shared project ${mine.name}.`;
            });
          }}
          onCancel={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "merge" && mine !== null && (
        <ConfirmDialog
          title={`Merge ${mine.name} and ${dialog.other.name}?`}
          body={
            `Merge only two shared projects that are the same real project. On every device ` +
            `they become one: the one with the smaller id stays as the root, and the other's ` +
            `usage folds into it. Tethra refuses the merge when both projects have spend caps.`
          }
          confirmLabel="Merge"
          danger
          onConfirm={() => {
            const other = dialog.other;
            setDialog(null);
            void act(async () => {
              const r = await api.meshProjectMerge(mine.mesh_project_id, other.mesh_project_id);
              setMergeWith("");
              return (
                `Merged: ${nameOf(r.merged)} (${shortId(r.merged)}) now folds into ` +
                `${nameOf(r.root)} (${shortId(r.root)}).`
              );
            });
          }}
          onCancel={() => setDialog(null)}
        />
      )}
    </>
  );
}
