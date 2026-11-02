// Devices view, outside a mesh: what the mesh is, then Create mesh or Join a
// mesh (Increment 09). The invite typed here is a bearer secret: it lives in
// this component's state only until the join succeeds, and never appears in
// an error message (MeshCommon.meshErrText).

import { useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { api } from "../api";
import { MESH_GUIDE_URL, meshErrText, shortId } from "./MeshCommon";

/** What the Devices view shows once this device is in a mesh. */
export interface MeshSetupOutcome {
  notice: string;
  /** Something the user must act on (the inviter could not be verified). */
  warning?: string;
}

export function MeshSetup(props: { onDone: (outcome?: MeshSetupOutcome) => void }) {
  const [guideError, setGuideError] = useState<string | null>(null);

  const openGuide = () => {
    setGuideError(null);
    void openUrl(MESH_GUIDE_URL).catch((e) => setGuideError(meshErrText(e)));
  };

  return (
    <section className="stack" aria-labelledby="mesh-setup-title">
      <h2 id="mesh-setup-title">This device is not in a mesh</h2>
      <p>
        Tethra Mesh keeps your own devices (a laptop, a desktop, a home server) in step: shared
        projects, cross-device API usage and spend caps. Your devices connect directly to each
        other over your LAN or a VPN you run, such as Tailscale.
      </p>
      <p>
        There is no Tethra server: devices only talk to each other, encrypted end to end.
        Credential values do not replicate.
      </p>
      <p>
        <button type="button" className="text-link" onClick={openGuide}>
          Read the mesh user guide
        </button>
      </p>
      {guideError && <p className="error">{guideError}</p>}
      <CreateMesh onDone={props.onDone} />
      <JoinMesh onDone={props.onDone} />
    </section>
  );
}

function CreateMesh(props: { onDone: (outcome?: MeshSetupOutcome) => void }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const r = await api.meshInit(name.trim());
      props.onDone({
        notice: `Created a mesh. This device is ${r.device_name} (${shortId(r.device_id)}).`,
      });
    } catch (err) {
      setError(meshErrText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="stack card" onSubmit={(e) => void submit(e)} aria-label="Create mesh">
      <h3>Create mesh</h3>
      <p className="muted">Start a new mesh with this device as its first member.</p>
      <label className="field">
        Device name
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
          autoComplete="off"
        />
        <span className="muted">Every device you pair sees this name.</span>
      </label>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div>
        <button type="submit" disabled={busy || name.trim() === ""}>
          {busy ? "Creating…" : "Create mesh"}
        </button>
      </div>
    </form>
  );
}

function JoinMesh(props: { onDone: (outcome?: MeshSetupOutcome) => void }) {
  const [invite, setInvite] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const r = await api.meshJoin(invite.trim(), name.trim());
      // The invite is spent: drop it from state before anything else renders.
      setInvite("");
      const first = r.first_exchange_completed
        ? `The first exchange received ${r.items_in} item(s).`
        : `The first exchange ended early after ${r.items_in} item(s); the next exchange continues.`;
      props.onDone({
        notice: `Joined the mesh as ${r.device_name} (${shortId(r.device_id)}). ${first}`,
        // Only a completed first exchange can prove the inviter's key; an
        // early end leaves it unverified without meaning anything is wrong.
        warning:
          r.first_exchange_completed && !r.inviter_verified
            ? "The inviting device's key does not match its roster entry. Leave this mesh " +
              "and pair again from a device you trust."
            : undefined,
      });
    } catch (err) {
      // Keep the invite so a typo can be fixed; never echo it in the error.
      setError(meshErrText(err, [invite]));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="stack card" onSubmit={(e) => void submit(e)} aria-label="Join a mesh">
      <h3>Join a mesh</h3>
      <p className="muted">
        On a device already in the mesh, open Devices and choose Pair a device (or run{" "}
        <code>tethra mesh invite</code>), then paste the invite here. Treat the invite like a
        password.
      </p>
      <label className="field">
        Invite
        <input
          type="text"
          value={invite}
          onChange={(e) => setInvite(e.target.value)}
          required
          autoComplete="off"
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          className="mono"
        />
      </label>
      <label className="field">
        Device name
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
          autoComplete="off"
        />
        <span className="muted">Every device in the mesh sees this name.</span>
      </label>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div>
        <button type="submit" disabled={busy || invite.trim() === "" || name.trim() === ""}>
          {busy ? "Joining…" : "Join mesh"}
        </button>
      </div>
    </form>
  );
}
