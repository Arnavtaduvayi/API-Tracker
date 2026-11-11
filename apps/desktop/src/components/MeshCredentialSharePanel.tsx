// "Share with my devices" on a credential's page (Tethra Mesh, Increment 11;
// ADR 0033). Shares this one credential with chosen paired devices: its value
// is sealed to each device's key and that device imports it only when asked.
// Lists where this credential is shared, revokes, and offers a reseal to
// devices that lack the current value.
//
// Security posture:
// - Share and reseal are reauthenticated in core; the dialogs are UX only.
// - No value is ever rendered or held here: the backend returns names,
//   devices and share ids only.
// - Nothing is shared, revoked or resealed on render: opening the panel only
//   reads (collecting shares addressed to removed devices first); every
//   change is one explicit click, and revoke asks first.
// - Revoking never revokes the credential at its provider: the notice says so,
//   says to revoke before rotating (a reseal offers every device holding the
//   old value unless its share was revoked; MD-4), and links to Rotation.
// - No analytics (MESH-SI-14).

import { useCallback, useEffect, useId, useState } from "react";
import { api } from "../api";
import type { Credential, MeshDeviceSummary, MeshSharesList, MeshStatus } from "../types";
import { ConfirmDialog } from "./ConfirmDialog";
import { ReauthDialog } from "./ReauthDialog";
import { meshDeviceLabel, meshErrText, scrubbed, shortId } from "./MeshCommon";

/** Shown wherever a share can be revoked (ADR 0033). */
export const REVOKE_NOTICE =
  "Revoking a share does not revoke the credential at its provider, and a device keeps " +
  "whatever it already imported. To cut a device off, revoke its share first, then rotate " +
  "the credential: a reseal never offers a device whose share you revoked.";

type Step =
  | { kind: "choose" }
  | { kind: "reauth"; devices: string[] | null }
  | { kind: "revoke"; shareId: string | null; label: string }
  | { kind: "reseal"; devices: string[] };

export function MeshCredentialSharePanel(props: {
  credential: Credential;
  onOpenRotation?: () => void;
}) {
  const titleId = useId();
  const c = props.credential;
  const [status, setStatus] = useState<MeshStatus | null>(null);
  const [bound, setBound] = useState<boolean | null>(null);
  const [shares, setShares] = useState<MeshSharesList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [step, setStep] = useState<Step | null>(null);
  const [allDevices, setAllDevices] = useState(true);
  const [picked, setPicked] = useState<Set<string>>(new Set());

  const reload = useCallback(async () => {
    try {
      const s = await api.meshStatus();
      setStatus(s);
      if (!s.initialized) return;
      const [rows, list] = await Promise.all([
        api.meshProjectsList(),
        api.meshSharesList(true),
      ]);
      setBound(rows.some((r) => r.bound_local_project === c.project_id));
      setShares(list);
      setError(null);
    } catch (e) {
      setError(meshErrText(e));
    }
  }, [c.project_id]);

  useEffect(() => {
    void reload();
  }, [reload, c.id]);

  if (status === null || !status.initialized) {
    // Outside a mesh there is nothing to share with; say nothing here.
    return error ? (
      <p className="error" role="alert">
        Could not read the mesh status: {error}
      </p>
    ) : null;
  }

  const others: MeshDeviceSummary[] = status.devices.filter((d) => d.active && !d.is_self);
  const label = (id: string) =>
    meshDeviceLabel(status.devices.find((d) => d.device_id === id)?.name ?? null, id);
  const mine = (shares?.outgoing ?? []).filter((r) => r.local_credential_id === c.id);
  const live = mine.filter((r) => !r.revoked);
  const offer = (shares?.reseal_offers ?? []).find((o) => o.credential_id === c.id);
  const offerDevices = offer
    ? Array.from(new Set([...offer.new_devices, ...offer.stale_devices]))
    : [];

  const share = async (password: string, devices: string[] | null) => {
    try {
      const r = await api.meshCredentialShare(password, c.id, devices);
      setNotice(
        `Shared ${r.credential_name} with ${r.recipients
          .map((x) => meshDeviceLabel(x.device_name, x.device_id))
          .join(", ")}. Each device can import it after its next exchange with this one.`,
      );
    } catch (e) {
      throw scrubbed(e, [password]);
    }
    void reload();
  };

  const reseal = async (password: string) => {
    try {
      const r = await api.meshCredentialReseal(password, c.id);
      setNotice(`Sealed the current value to ${r.recipients.length} device(s).`);
    } catch (e) {
      throw scrubbed(e, [password]);
    }
    void reload();
  };

  const revoke = async (shareId: string | null) => {
    setError(null);
    try {
      const out = shareId
        ? await api.meshShareRevoke(shareId)
        : await api.meshCredentialRevoke(c.id);
      setNotice(`Revoked ${out.length} share(s). ${REVOKE_NOTICE}`);
    } catch (e) {
      setError(meshErrText(e));
    }
    void reload();
  };

  const chosen = allDevices ? null : Array.from(picked);
  const recipientsText = chosen
    ? chosen.map(label).join(", ")
    : `all your devices (${others.map((d) => label(d.device_id)).join(", ")}), and devices ` +
      "you pair later as a reseal offer";

  return (
    <section className="card stack" aria-labelledby={titleId}>
      <h2 id={titleId}>Shared with my devices</h2>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {notice && (
        <p className="notice" role="status">
          {notice}
        </p>
      )}
      {c.is_reference ? (
        <p className="muted">This record is a reference; share the credential it points to.</p>
      ) : bound === false ? (
        <p className="muted">
          To share this credential with your devices, first share its project with them (on the
          project&apos;s page).
        </p>
      ) : (
        <>
          <p className="muted" style={{ margin: 0 }}>
            The value is sealed to each device you choose and stays sealed until that device
            imports it, which needs its master password. Nothing is shared or imported by
            itself.
          </p>
          <div>
            <button
              type="button"
              disabled={others.length === 0 || bound === null}
              onClick={() => {
                setNotice(null);
                setAllDevices(true);
                setPicked(new Set());
                setStep({ kind: "choose" });
              }}
            >
              Share with my devices…
            </button>
            {others.length === 0 && (
              <span className="muted"> Pair another device first (Devices page).</span>
            )}
          </div>
        </>
      )}

      {mine.length > 0 && (
        <div style={{ overflowX: "auto" }}>
          <table>
            <thead>
              <tr>
                <th scope="col">Device</th>
                <th scope="col">Share</th>
                <th scope="col">Value version</th>
                <th scope="col">State</th>
                <th scope="col">
                  <span className="muted">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {mine.map((r) => (
                <tr key={r.share_id}>
                  <td>{meshDeviceLabel(r.recipient_name, r.recipient)}</td>
                  <td>
                    <code>{shortId(r.share_id)}</code>
                  </td>
                  <td>v{r.value_version}</td>
                  <td>
                    {r.revoked
                      ? "revoked"
                      : r.superseded_by !== null
                        ? `replaced at the device by ${label(r.superseded_by)}'s share (reseal to send yours)`
                        : r.current_value_version !== null &&
                            r.current_value_version > r.value_version
                          ? `older value (now v${r.current_value_version})`
                          : "shared"}
                  </td>
                  <td>
                    {!r.revoked && (
                      <button
                        type="button"
                        aria-label={`Revoke the share to ${meshDeviceLabel(r.recipient_name, r.recipient)}`}
                        onClick={() =>
                          setStep({
                            kind: "revoke",
                            shareId: r.share_id,
                            label: meshDeviceLabel(r.recipient_name, r.recipient),
                          })
                        }
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {live.length > 1 && (
        <div>
          <button
            type="button"
            onClick={() => setStep({ kind: "revoke", shareId: null, label: "every device" })}
          >
            Revoke every share of this credential
          </button>
        </div>
      )}
      {offer && offerDevices.length > 0 && (
        <div className="warnbox">
          <p style={{ margin: 0 }}>
            {offerDevices.map(label).join(", ")} {offerDevices.length === 1 ? "does" : "do"} not
            have this credential&apos;s current value
            {offer.new_devices.length > 0
              ? " (paired after you shared it with all your devices)"
              : ""}
            . Nothing is sent until you reseal it.
          </p>
          <button
            type="button"
            onClick={() => setStep({ kind: "reseal", devices: offerDevices })}
          >
            Reseal…
          </button>
        </div>
      )}
      {mine.length > 0 && (
        <p className="muted" style={{ margin: 0 }}>
          {REVOKE_NOTICE}{" "}
          {props.onOpenRotation && (
            <button type="button" className="link" onClick={props.onOpenRotation}>
              Open Rotation
            </button>
          )}
        </p>
      )}

      {step?.kind === "choose" && (
        <dialog open aria-labelledby={`${titleId}-choose`}>
          <h2 id={`${titleId}-choose`}>Share {c.name} with my devices</h2>
          <p>{REVOKE_NOTICE}</p>
          <form
            className="stack"
            onSubmit={(e) => {
              e.preventDefault();
              setStep({ kind: "reauth", devices: chosen });
            }}
          >
            <label>
              <input
                type="radio"
                name="share-to"
                checked={allDevices}
                onChange={() => setAllDevices(true)}
              />{" "}
              All my devices (and offer it to devices I pair later)
            </label>
            <label>
              <input
                type="radio"
                name="share-to"
                checked={!allDevices}
                onChange={() => setAllDevices(false)}
              />{" "}
              Only these devices:
            </label>
            {!allDevices &&
              others.map((d) => (
                <label key={d.device_id} style={{ marginLeft: "1.5rem" }}>
                  <input
                    type="checkbox"
                    checked={picked.has(d.device_id)}
                    onChange={(e) => {
                      const next = new Set(picked);
                      if (e.target.checked) next.add(d.device_id);
                      else next.delete(d.device_id);
                      setPicked(next);
                    }}
                  />{" "}
                  {label(d.device_id)}
                </label>
              ))}
            <div style={{ display: "flex", gap: "0.5rem" }}>
              <button type="submit" disabled={!allDevices && picked.size === 0}>
                Continue
              </button>
              <button type="button" onClick={() => setStep(null)}>
                Cancel
              </button>
            </div>
          </form>
        </dialog>
      )}
      {step?.kind === "reauth" && (
        <ReauthDialog
          title={`Share ${c.name}`}
          actionLabel="Share"
          body={`Seal this credential's value to ${recipientsText}.`}
          onConfirm={(pw) => share(pw, step.devices)}
          onClose={() => setStep(null)}
        />
      )}
      {step?.kind === "revoke" && (
        <ConfirmDialog
          title={`Revoke the share to ${step.label}?`}
          body={REVOKE_NOTICE}
          confirmLabel="Revoke"
          danger
          onConfirm={() => {
            const id = step.shareId;
            setStep(null);
            void revoke(id);
          }}
          onCancel={() => setStep(null)}
        />
      )}
      {step?.kind === "reseal" && (
        <ReauthDialog
          title={`Reseal ${c.name}`}
          actionLabel="Reseal"
          body={`Seal the current value to ${step.devices.map(label).join(", ")}.`}
          onConfirm={reseal}
          onClose={() => setStep(null)}
        />
      )}
    </section>
  );
}
