// Small helpers shared by the Devices view's components (Tethra Mesh,
// Increment 09). No analytics here or anywhere in the mesh UI (MESH-SI-14).

import { isApiError } from "../api";
import type { ApiError } from "../types";
import { formatMicros } from "../utils";

/** Where the Devices view sends "Read the mesh user guide". */
export const MESH_GUIDE_URL =
  "https://github.com/Arnavtaduvayi/API-Tracker/blob/main/docs/mesh/USER_GUIDE.md";

const INVITE_PATTERN = /tethra-mesh-invite:\S+/g;

/**
 * The text to show for a failed mesh command.
 *
 * Backend errors (`ErrDto`) carry an already-redacted `message`; anything else
 * becomes a generic sentence rather than a stringified object. As defence in
 * depth, anything that looks like an invite, and every `secrets` value the
 * user typed for this action (the invite, the master password), is blanked
 * out, so a misbehaving message can never echo a bearer secret on screen.
 */
export function meshErrText(e: unknown, secrets: string[] = []): string {
  let text = isApiError(e) ? e.message : "The request failed. Try again.";
  text = text.replace(INVITE_PATTERN, "[invite hidden]");
  for (const secret of secrets) {
    const s = secret.trim();
    if (s.length >= 4) text = text.split(s).join("[hidden]");
  }
  return text;
}

/**
 * For a `ReauthDialog` `onConfirm`: rethrow a failure as an `ApiError` whose
 * message went through `meshErrText`, so the dialog (which shows
 * `err.message`) never shows the typed password.
 */
export function scrubbed(e: unknown, secrets: string[]): ApiError {
  return { code: isApiError(e) ? e.code : "unknown", message: meshErrText(e, secrets) };
}

/** The first 8 hex characters of a device or mesh id. */
export function shortId(hex: string): string {
  return hex.slice(0, 8);
}

/**
 * Whether `addr` (an `IP:PORT` literal) is a loopback address: 127.x.x.x or
 * [::1]. Anything else, including text that does not parse, is treated as
 * reachable from the network: the safe reading, and the one core uses.
 */
export function isLoopbackAddr(addr: string): boolean {
  const a = addr.trim();
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$/.test(a) || /^\[::1\]:\d{1,5}$/.test(a);
}

// --- Increment 10: shared projects, cross-device usage and spend caps. ---
// Display formatting only: every figure, label and flag comes from core.

/**
 * `formatMicros` for an amount that may be negative (a device's available
 * spend-cap rights once it has gone over): "-$0.50" rather than "$-0.50".
 * Display only; the value is core's.
 */
export function formatSignedMicros(micros: number): string {
  return micros < 0 ? `-${formatMicros(-micros)}` : formatMicros(micros);
}

/** "name (1a2b3c4d)", or "unnamed (1a2b3c4d)": how mesh tables name a device. */
export function meshDeviceLabel(name: string | null | undefined, id: string): string {
  return `${name ?? "unnamed"} (${shortId(id)})`;
}

/**
 * A dollar amount the user typed, echoed back in a confirmation exactly as
 * typed (with one leading "$"). Never parsed here: core parses the text.
 */
export function typedUsd(text: string): string {
  const t = text.trim();
  return t.startsWith("$") ? t : `$${t}`;
}
