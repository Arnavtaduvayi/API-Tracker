// Devices view: the Tethra Mesh device workflow without the CLI (ADR 0031,
// Increment 09). Outside a mesh it offers Create mesh or Join a mesh; inside
// one it shows this device and its node, the device list (pair, remove), the
// peers, health, and Leave mesh.
//
// Security posture:
// - No analytics: this view emits no event and no `screen_view` (MESH-SI-14).
// - No key material is ever rendered. The only bearer secret is a pairing
//   invite, shown once in its own dialog and dropped from state on close.
// - Every reauthenticated action (pair, remove, leave, opening the node to
//   the network) is re-verified in core; the dialogs here are UX only.
// - The status poll uses lock-free/background reads, so leaving this view
//   open does not hold off inactivity auto-lock.

import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api";
import type { MeshStatus } from "../types";
import { ConfirmDialog } from "./ConfirmDialog";
import { ReauthDialog } from "./ReauthDialog";
import { MeshSetup, type MeshSetupOutcome } from "./MeshSetup";
import { MeshThisDevice } from "./MeshThisDevice";
import { MeshDeviceList } from "./MeshDeviceList";
import { MeshPeers } from "./MeshPeers";
import { MeshHealth } from "./MeshHealth";
import { MeshAvailableProjects } from "./MeshAvailableProjects";
import { meshErrText, scrubbed } from "./MeshCommon";

/** How often the open view re-reads the mesh status, devices and peers. */
const POLL_MS = 10_000;

export function DevicesView() {
  const [status, setStatus] = useState<MeshStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<MeshSetupOutcome | null>(null);
  const [leaveStep, setLeaveStep] = useState<"confirm" | "reauth" | null>(null);
  /** Bumped on every poll and after every action; the panels reload on it. */
  const [refreshKey, setRefreshKey] = useState(0);

  const seq = useRef(0);
  const mounted = useRef(true);

  const reload = useCallback(async () => {
    const mine = ++seq.current;
    try {
      const s = await api.meshStatus();
      // A slower, older read must not overwrite a newer one.
      if (!mounted.current || mine !== seq.current) return;
      setStatus(s);
      setError(null);
    } catch (e) {
      if (!mounted.current || mine !== seq.current) return;
      setError(meshErrText(e));
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload, refreshKey]);

  useEffect(() => {
    mounted.current = true;
    const timer = setInterval(() => setRefreshKey((k) => k + 1), POLL_MS);
    return () => {
      mounted.current = false;
      clearInterval(timer);
    };
  }, []);

  const changed = useCallback(() => setRefreshKey((k) => k + 1), []);

  const leave = async (password: string) => {
    try {
      const r = await api.meshLeave(password);
      setOutcome({
        notice: r.delivered
          ? "Left the mesh; another device received this device's departure."
          : "Left the mesh. No other device was reachable, so they still list this one " +
            "until one of them removes it.",
      });
    } catch (e) {
      throw scrubbed(e, [password]);
    }
    changed();
  };

  return (
    <div>
      <div className="screen-heading">
        <div>
          <p className="screen-kicker">Tethra Mesh</p>
          <h1>Devices</h1>
        </div>
      </div>
      {error && (
        <p className="error" role="alert">
          Could not read the mesh status: {error}
        </p>
      )}
      {outcome && (
        <div className="notice" role="status">
          <p style={{ margin: 0 }}>{outcome.notice}</p>
          <button type="button" className="link" onClick={() => setOutcome(null)}>
            Dismiss
          </button>
        </div>
      )}
      {outcome?.warning && (
        <p className="warnbox" role="alert">
          {outcome.warning}
        </p>
      )}
      {status === null && !error && <p className="muted">Loading…</p>}
      {status !== null && !status.initialized && (
        <MeshSetup
          onDone={(o) => {
            setOutcome(o ?? null);
            changed();
          }}
        />
      )}
      {status !== null && status.initialized && (
        <>
          <MeshThisDevice status={status} onChanged={changed} />
          <MeshDeviceList refreshKey={refreshKey} onChanged={changed} />
          {/* Tethra Mesh (Increment 10): shared projects not bound here. */}
          <MeshAvailableProjects
            refreshKey={refreshKey}
            devices={status.devices}
            onChanged={changed}
          />
          <MeshPeers refreshKey={refreshKey} onChanged={changed} />
          <MeshHealth onChanged={changed} />

          <section
            className="card stack"
            aria-labelledby="mesh-leave-title"
            style={{ marginTop: "2rem" }}
          >
            <h2 id="mesh-leave-title">Leave mesh</h2>
            <p className="muted">
              Removes this device from the mesh and deletes its mesh identity, keys and every
              mesh record here; the gateway stops enforcing spend caps. Your local projects and
              credentials stay.
            </p>
            <div>
              <button type="button" className="danger" onClick={() => setLeaveStep("confirm")}>
                Leave mesh
              </button>
            </div>
          </section>
        </>
      )}

      {leaveStep === "confirm" && (
        <ConfirmDialog
          title="Leave the mesh?"
          body={
            "This deletes this device's mesh identity, keys and records here; to rejoin, " +
            "pair again with a new invite."
          }
          confirmLabel="Leave mesh"
          danger
          onConfirm={() => setLeaveStep("reauth")}
          onCancel={() => setLeaveStep(null)}
        />
      )}
      {leaveStep === "reauth" && (
        <ReauthDialog
          title="Leave the mesh"
          actionLabel="Leave mesh"
          body={
            "The app stops its mesh node, tries to tell another device that this one is " +
            "leaving, then deletes this device's mesh state."
          }
          onConfirm={leave}
          onClose={() => setLeaveStep(null)}
        />
      )}
    </div>
  );
}
