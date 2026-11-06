// The pairing invite, shown once (Increment 09). The invite string is a
// bearer secret until it expires: anyone holding it can add a device to the
// mesh. It is rendered only here, never logged, and the parent drops it from
// its state when this dialog closes. Once it expires it is no longer rendered.

import { useEffect, useState } from "react";
import type { MeshInvite } from "../types";
import { isLoopbackAddr } from "./MeshCommon";

/** "9:05" from a number of milliseconds (never negative). */
function mmss(ms: number): string {
  const total = Math.max(0, Math.ceil(ms / 1000));
  const m = Math.floor(total / 60);
  const s = total % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

/**
 * Copy to the clipboard, reporting honestly when it is unavailable rather
 * than pretending it worked (the same approach as TrackFlow).
 */
async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (!navigator.clipboard?.writeText) return false;
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function MeshPairDialog(props: { invite: MeshInvite; onClose: () => void }) {
  const { invite } = props;
  const expiresAt = Date.parse(invite.expires_at);
  const [now, setNow] = useState(() => Date.now());
  const [copy, setCopy] = useState<"idle" | "copied" | "failed">("idle");

  // An unreadable expiry is shown without a countdown rather than hiding an
  // invite the user just reauthenticated for; the backend still enforces it.
  const known = !Number.isNaN(expiresAt);
  const remaining = known ? expiresAt - now : Number.POSITIVE_INFINITY;
  const expired = remaining <= 0;

  useEffect(() => {
    if (expired) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [expired]);

  const onCopy = async () => {
    setCopy((await copyToClipboard(invite.invite)) ? "copied" : "failed");
  };

  const loopbackOnly =
    invite.addresses.length > 0 && invite.addresses.every((a) => isLoopbackAddr(a));

  return (
    <dialog open aria-labelledby="mesh-pair-title">
      <h2 id="mesh-pair-title">Pair a device</h2>
      {expired ? (
        <p className="warnbox" role="alert">
          This invite expired and is no longer shown. Close this dialog and create a new one if
          you still need to pair a device.
        </p>
      ) : (
        <>
          <p className="warnbox" role="alert">
            Treat this invite like a password for the next {invite.ttl_minutes} minutes: anyone
            who has it can add a device to your mesh. Move it over a channel you trust (type it,
            or use your own password manager); it is shown once.
          </p>
          <p>
            <strong>Invite (shown once):</strong>
          </p>
          <p className="mono" style={{ userSelect: "all", wordBreak: "break-all" }}>
            {invite.invite}
          </p>
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
            <button type="button" onClick={() => void onCopy()}>
              Copy invite
            </button>
            {known && <span className="muted">Expires in {mmss(remaining)}</span>}
          </div>
          {copy === "copied" && (
            <p className="notice">
              Copied. Your clipboard keeps the invite until you copy something else, and other
              apps can read it; paste it on the new device soon.
            </p>
          )}
          {copy === "failed" && (
            <p className="error">
              The clipboard is not available here. Select the invite above and copy it.
            </p>
          )}
        </>
      )}
      <p>
        The new device connects to{" "}
        {invite.addresses.length === 0
          ? "this device's node"
          : invite.addresses.map((a, i) => (
              <span key={a}>
                {i > 0 && ", "}
                <code>{a}</code>
              </span>
            ))}
        .
      </p>
      {loopbackOnly && (
        <p className="muted">
          These are loopback addresses: only a device on this same computer can reach them. To
          pair another machine, give the node a LAN or VPN listen address under This device.
        </p>
      )}
      <p className="muted">
        On the new device: open Devices, choose Join a mesh and paste the invite (or run{" "}
        <code>tethra mesh join -</code> and paste it, which keeps it out of your shell history).
      </p>
      <div>
        <button type="button" onClick={props.onClose}>
          Close
        </button>
      </div>
    </dialog>
  );
}
