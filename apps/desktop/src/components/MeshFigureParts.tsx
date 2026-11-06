// Small pieces the cross-device usage card and the spend-cap panel share
// (Tethra Mesh, Increment 10): how a device is named and badged in a table,
// how "as of" is shown, and core's fixed honesty notes. Every flag shown here
// (this device, stale, removed, as of) is core's; nothing is decided here.

import { relativeTime } from "../useLiveRefresh";
import { formatTimestamp } from "../utils";
import { shortId } from "./MeshCommon";

/** A device's name, short id and badges, for the first cell of a mesh table row. */
export function MeshDeviceCell(props: {
  id: string;
  name: string | null;
  isSelf: boolean;
  stale: boolean;
  removed: boolean;
  /** Extra badges after the standard ones (e.g. "owner"). */
  children?: React.ReactNode;
}) {
  return (
    <span style={{ display: "inline-flex", gap: "0.3rem", flexWrap: "wrap" }}>
      <span>{props.name ?? <span className="muted">unnamed</span>}</span>
      <code>{shortId(props.id)}</code>
      {props.isSelf && <span className="badge ok">this device</span>}
      {props.stale && <span className="badge warn">stale</span>}
      {props.removed && <span className="badge bad">removed</span>}
      {props.children}
    </span>
  );
}

/**
 * When a device's figures are from: this device's own are current; another
 * device's are as of the last successful exchange with it, or it was never
 * exchanged with directly.
 */
export function MeshAsOf(props: { isSelf: boolean; asOf: string | null }) {
  if (props.isSelf) return <span>current</span>;
  if (props.asOf === null) return <span className="muted">never exchanged</span>;
  return <span title={formatTimestamp(props.asOf)}>{relativeTime(props.asOf)}</span>;
}

/** Core's fixed honesty notes, shown with the figures they qualify. */
export function MeshNotes(props: { notes: string[] }) {
  if (props.notes.length === 0) return null;
  return (
    <ul className="muted" style={{ margin: 0, paddingLeft: "1.2rem" }}>
      {props.notes.map((n) => (
        <li key={n}>{n}</li>
      ))}
    </ul>
  );
}
