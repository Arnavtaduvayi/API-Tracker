// The "Track API activity" flow (ADR 0022 D6): folder picker → bounded
// scan → ONE review screen (coverage + per-destination approval + exact
// diff + disclosure + optional password) → orchestrated apply with per-step
// honest reporting → restart guidance only when needed → first-request
// verification.
//
// Two rules shape this screen.
//
// 1. Project content may SUGGEST a destination; it may never AUTHORIZE one
//    (ADR 0024). Every destination read out of the user's own files gets its
//    own checkbox, unchecked, with the full disclosure the shared Rust
//    `OriginApprovalRequest` renders. "Start tracking" reads those
//    approvals; it cannot create one.
// 2. The screen must not imply coverage it does not have. The headline is
//    the shared `CoverageSummary`, which accounts for every integration the
//    scan saw — including the ones Tethra cannot identify at all (ZFT-010).
//
// Every state distinguishes loading / empty / error / unsupported: no
// promise chain here discards an error, and no empty list renders without
// saying why and what to do next.
import { useCallback, useEffect, useRef, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, isApiError } from "../api";
import type {
  TrackingApplyReport,
  TrackingDiagnosis,
  TrackingOriginRequest,
  TrackingPlan,
  TrackingProvider,
  TrackingScan,
  TrackingStatus,
} from "../types";

type Phase =
  | { name: "idle" }
  | { name: "scanning"; folder: string }
  | { name: "review"; scan: TrackingScan }
  | { name: "applying" }
  | { name: "waiting"; report: TrackingApplyReport }
  | { name: "verified"; status: TrackingStatus }
  | { name: "attention"; report: TrackingApplyReport | null };

function errText(e: unknown): string {
  return isApiError(e) ? e.message : String(e);
}

/** 2 s while waiting for the first request (ADR 0022, O-22-4). */
const POLL_MS = 2000;
/** Show the restart instruction after this long with no traffic. */
const RESTART_HINT_MS = 10_000;
/** Stop watching and offer diagnostics after this long with no traffic. */
const DIAGNOSE_MS = 120_000;

/**
 * How many unrecognised variables to enumerate. The exact total is always
 * stated, so the list is bounded without ever becoming a partial count.
 */
const UNRECOGNIZED_DISPLAY_LIMIT = 12;

/**
 * A long review must stay ONE screen: with thirty detected APIs the user
 * still has to reach the diff and the Start button. Each list scrolls
 * inside itself instead of pushing the decision off the page.
 */
const LIST_SCROLL: React.CSSProperties = {
  maxHeight: "20rem",
  overflowY: "auto",
};

/**
 * Copy to the clipboard, reporting honestly when it is unavailable rather
 * than pretending it worked. The caller renders the text as selectable
 * fallback either way, so the action never becomes a dead button.
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

/** The manual instruction for a provider Tethra cannot configure itself. */
function manualInstruction(p: TrackingProvider, folder: string): string {
  return [
    `Tethra cannot configure ${p.display_name} automatically in ${folder}.`,
    p.unsupported_reason ?? "",
    ...p.limitations,
    "",
    "To route it through Tethra by hand you need two things:",
    "  1. the exact HTTPS base URL its SDK talks to;",
    "  2. an SDK setting (environment variable or client option) that",
    "     overrides that base URL.",
    "",
    "If both exist, add the destination under Advanced → Gateway internals,",
    "then point the SDK's base-URL setting at the local address Tethra shows",
    "for it. If the second one does not exist, this API cannot be observed",
    "through a local proxy at all, and no setting will change that.",
  ]
    .filter((line) => line !== undefined)
    .join("\n");
}

/** A support request the user can paste wherever they choose to file it. */
function supportRequestText(
  names: string[],
  folder: string,
  version: "unrecognized" | "unsupported",
): string {
  return [
    version === "unrecognized"
      ? "Provider support request: Tethra found credentials it has no provider definition for."
      : "Provider support request: Tethra recognises these providers but cannot observe them.",
    "",
    `Detected in: ${folder}`,
    "Variable names (no values):",
    ...names.map((n) => `  ${n}`),
    "",
    "What would help: the provider's HTTPS base URL and the SDK setting that",
    "overrides it. Nothing in this text is sent anywhere by Tethra — it is",
    "copied to your clipboard for you to file wherever you choose.",
  ].join("\n");
}

export function TrackFlow({
  onDone,
  onOpenAdvanced,
}: {
  onDone: () => void;
  /** Navigate to Advanced → Gateway internals (the manual route form). */
  onOpenAdvanced?: () => void;
}) {
  const [phase, setPhase] = useState<Phase>({ name: "idle" });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Review-screen state.
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [originRequests, setOriginRequests] = useState<TrackingOriginRequest[] | null>(null);
  const [originError, setOriginError] = useState<string | null>(null);
  const [typedOrigins, setTypedOrigins] = useState<Record<string, string>>({});
  const [approvedTyped, setApprovedTyped] = useState<Set<string>>(new Set());
  const [plan, setPlan] = useState<TrackingPlan | null>(null);
  const [planError, setPlanError] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [copied, setCopied] = useState<string | null>(null);
  const [copyFallback, setCopyFallback] = useState<string | null>(null);

  // Waiting-state bookkeeping.
  const [waitedMs, setWaitedMs] = useState(0);
  const [diagnoses, setDiagnoses] = useState<TrackingDiagnosis[] | null>(null);
  const [diagnosing, setDiagnosing] = useState(false);
  // Watching is re-armable: a 120 s cutoff and a transient IPC failure both
  // used to end polling FOREVER while the screen kept rendering "Waiting for
  // traffic…", so a user who made a request one second later was told
  // nothing, permanently (ZFT-015).
  const [watchAttempt, setWatchAttempt] = useState(0);
  const [watchStopped, setWatchStopped] = useState<string | null>(null);
  const pollRef = useRef<number | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current !== null) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  useEffect(() => stopPolling, [stopPolling]);

  async function pickFolder() {
    setError(null);
    try {
      const picked = await open({
        directory: true,
        multiple: false,
        title: "Select the project folder to track",
      });
      if (typeof picked !== "string") return; // cancelled
      await scan(picked);
    } catch (e) {
      setError(`The folder picker could not open: ${errText(e)}`);
    }
  }

  async function scan(folder: string) {
    setPhase({ name: "scanning", folder });
    setError(null);
    setPlan(null);
    setPlanError(null);
    setOriginRequests(null);
    setOriginError(null);
    setTypedOrigins({});
    setApprovedTyped(new Set());
    setExpanded(new Set());
    setCopied(null);
    setCopyFallback(null);
    try {
      const result = await api.trackingScan(folder);
      // Only manifest-origin providers are ever pre-selected. Anything whose
      // destination came from the project starts unselected AND unapproved.
      setSelected(
        new Set(
          result.providers.filter((p) => p.selected_by_default).map((p) => p.provider_id),
        ),
      );
      setPhase({ name: "review", scan: result });
      try {
        setOriginRequests(await api.trackingOriginRequests());
      } catch (e) {
        setOriginRequests([]);
        setOriginError(errText(e));
      }
    } catch (e) {
      setError(errText(e));
      setPhase({ name: "idle" });
    }
  }

  // Rebuild the plan whenever the selection changes — the diff on screen
  // is always the diff that would be applied. Destinations are NOT sent:
  // the backend reads them from the approvals recorded below, so this call
  // cannot introduce one.
  useEffect(() => {
    if (phase.name !== "review") return;
    if (selected.size === 0) {
      setPlan(null);
      setPlanError(null);
      return;
    }
    let cancelled = false;
    api
      .trackingPlanBuild([...selected])
      .then((p) => {
        if (!cancelled) {
          setPlan(p);
          setPlanError(null);
        }
      })
      .catch((e) => {
        if (!cancelled) {
          setPlan(null);
          setPlanError(errText(e));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [phase.name, selected]);

  /**
   * Approve or withdraw ONE destination. Separate from selection and from
   * applying: this is the only call that can authorize a destination, and
   * the user has to make it per origin.
   */
  async function toggleOriginApproval(providerId: string, origin: string, approve: boolean) {
    setOriginError(null);
    try {
      if (approve) {
        await api.trackingOriginApprove(providerId, origin);
      } else {
        await api.trackingOriginRevoke(providerId);
      }
      setOriginRequests(await api.trackingOriginRequests());
      setSelected((prev) => {
        const next = new Set(prev);
        if (approve) next.add(providerId);
        else next.delete(providerId);
        return next;
      });
    } catch (e) {
      setOriginError(errText(e));
      // Leave the checkbox reflecting the backend, not the click.
      try {
        setOriginRequests(await api.trackingOriginRequests());
      } catch {
        /* the error above already says the approval did not take effect */
      }
    }
  }

  /** A typed destination for a provider whose origin could not be inferred. */
  async function toggleTypedOrigin(providerId: string, approve: boolean) {
    const origin = (typedOrigins[providerId] ?? "").trim();
    setOriginError(null);
    try {
      if (approve) {
        if (origin.length === 0) return;
        await api.trackingOriginApprove(providerId, origin);
        setApprovedTyped((prev) => new Set(prev).add(providerId));
        setSelected((prev) => new Set(prev).add(providerId));
      } else {
        await api.trackingOriginRevoke(providerId);
        setApprovedTyped((prev) => {
          const next = new Set(prev);
          next.delete(providerId);
          return next;
        });
        setSelected((prev) => {
          const next = new Set(prev);
          next.delete(providerId);
          return next;
        });
      }
    } catch (e) {
      setOriginError(errText(e));
    }
  }

  async function startTracking() {
    setBusy(true);
    setError(null);
    setPhase({ name: "applying" });
    try {
      const report = await api.trackingApply(password.length > 0 ? password : null);
      setPassword("");
      if (report.failed) {
        setPhase({ name: "attention", report });
        return;
      }
      setWaitedMs(0);
      setDiagnoses(null);
      setWatchStopped(null);
      setWatchAttempt((n) => n + 1);
      setPhase({ name: "waiting", report });
    } catch (e) {
      setError(errText(e));
      setPhase({ name: "attention", report: null });
    } finally {
      setBusy(false);
    }
  }

  // Poll for the first observed request. Ending a watch is a state change
  // the user can see and undo, never a silent permanent stop.
  useEffect(() => {
    if (phase.name !== "waiting") return;
    const setupId = phase.report.setup_id;
    if (!setupId) return;
    const started = Date.now();
    const tick = async () => {
      try {
        const status = await api.trackingStatus(setupId);
        setWaitedMs(Date.now() - started);
        if (status.watch === "observed" || status.watch === "partial") {
          stopPolling();
          setPhase({ name: "verified", status });
        } else if (Date.now() - started >= DIAGNOSE_MS) {
          stopPolling();
          setWatchStopped(
            "Tethra stopped watching after two minutes with no traffic. It is not " +
              "watching now — nothing on this screen updates until you check again.",
          );
          void runDiagnosis(setupId);
        }
      } catch (e) {
        // A transient IPC failure is not a reason to stop forever.
        stopPolling();
        setWatchStopped(
          `Watching stopped because the tracking state could not be read: ${errText(e)}`,
        );
      }
    };
    pollRef.current = window.setInterval(() => void tick(), POLL_MS);
    void tick();
    return stopPolling;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase.name, watchAttempt]);

  /** Re-arm the watch after a cutoff or an error (ZFT-015). */
  function checkAgain() {
    setWatchStopped(null);
    setWaitedMs(0);
    setWatchAttempt((n) => n + 1);
  }

  async function runDiagnosis(setupId: string) {
    setDiagnosing(true);
    try {
      const found = await api.trackingDiagnose(setupId);
      setDiagnoses(found);
    } catch (e) {
      setError(`Diagnostics could not run: ${errText(e)}`);
    } finally {
      setDiagnosing(false);
    }
  }

  async function startForegroundFallback() {
    setBusy(true);
    try {
      await api.trackingForegroundStart();
      setError(null);
      setPhase({ name: "idle" });
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  }

  async function copyAction(label: string, text: string) {
    const ok = await copyToClipboard(text);
    setCopied(ok ? label : null);
    setCopyFallback(ok ? null : text);
  }

  function toggleExpanded(key: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  // ---- render ---------------------------------------------------------

  if (phase.name === "idle") {
    return (
      <section className="stack">
        <h1>Track API activity</h1>
        <p>
          Tethra can watch a project&apos;s API traffic locally and show requests, errors,
          latency, tokens, and estimated cost — metadata only, never prompts, keys, or bodies.
        </p>
        {/* The scope, BEFORE the folder picker. Stating it afterwards is
            what turned an unsupported project into a dead end the user had
            already invested in (ZFT-009). */}
        <h2>What Tethra can and cannot track</h2>
        <p>
          Tethra observes an API by pointing its SDK&apos;s base-URL setting at a local address.
          That works only when the SDK has such a setting and Tethra knows the API&apos;s real
          address. Where either is missing, Tethra will say so by name rather than pretend
          otherwise — and the rest of the project is still configured.
        </p>
        {error && (
          <p className="error" role="alert">
            {error}{" "}
            <button className="link" onClick={() => void pickFolder()}>
              Try again
            </button>
          </p>
        )}
        <div>
          <button onClick={() => void pickFolder()}>Select project folder</button>{" "}
          <button className="link" onClick={onDone}>
            Cancel
          </button>
        </div>
      </section>
    );
  }

  if (phase.name === "scanning") {
    return (
      <section className="stack">
        <h1>Track API activity</h1>
        <p>Scanning {phase.folder}…</p>
        <p className="muted">Only this folder is read. Nothing is uploaded or executed.</p>
      </section>
    );
  }

  if (phase.name === "review") {
    const scan = phase.scan;
    const automatic = scan.providers.filter((p) => p.configurability === "automatic");
    const needsInput = scan.providers.filter((p) => p.configurability === "needs_origin_input");
    const unsupported = scan.providers.filter((p) => p.configurability === "unsupported");
    const requests = originRequests ?? [];
    const [headline, ...restLines] = scan.coverage_lines;
    const nothingFound = scan.coverage.total === 0 && scan.providers.length === 0;

    // The actions offered for an API Tethra cannot configure. Every one of
    // these does something here, in the app. Telling a desktop-only user to
    // run a CLI command is not an action (ZFT-009).
    const unsupportedNames = [
      ...unsupported.map((p) => p.display_name),
      ...scan.unrecognized.map((u) => u.var),
    ];

    return (
      <section className="stack">
        <h1>{headline ?? `Nothing detected in ${scan.folder}`}</h1>
        <p className="mono muted">{scan.folder}</p>
        {restLines.length > 0 && (
          <ul>
            {restLines.map((line, i) => (
              <li key={i}>{line}</li>
            ))}
          </ul>
        )}
        {scan.scan_gaps && (
          <p className="muted">Not everything could be inspected: {scan.scan_gaps}</p>
        )}
        {scan.git_warnings.map((w, i) => (
          <p className="muted" key={`git-${i}`}>
            ! {w}
          </p>
        ))}
        {scan.already_tracking && (
          <p className="notice">
            This folder is already tracked. Re-running setup is safe: existing routes and links
            are reused, not duplicated.
          </p>
        )}

        {nothingFound && (
          <>
            <p>
              Tethra looked at .env files, package manifests, and lockfiles (
              {scan.scanned_files} file(s) read, 6 levels deep, nothing executed or uploaded)
              and found no credential or SDK it recognises.
            </p>
            <div>
              <button onClick={() => void pickFolder()}>Choose a different folder</button>{" "}
              {onOpenAdvanced && (
                <button className="link" onClick={onOpenAdvanced}>
                  Add a destination by hand (Advanced)
                </button>
              )}{" "}
              <button className="link" onClick={onDone}>
                Cancel
              </button>
            </div>
          </>
        )}

        {/* --- configured from a Tethra manifest ------------------------ */}
        {automatic.length > 0 && (
          <>
            <h2>Tethra knows where these go</h2>
            <p className="muted">
              Their destination comes from a Tethra provider definition built into this app, so
              nothing in your project can change it.
            </p>
            <ul className="stack" style={LIST_SCROLL}>
              {automatic.map((p) => (
                <li key={p.provider_id}>
                  <label>
                    <input
                      type="checkbox"
                      checked={selected.has(p.provider_id)}
                      onChange={(e) => {
                        const next = new Set(selected);
                        if (e.target.checked) next.add(p.provider_id);
                        else next.delete(p.provider_id);
                        setSelected(next);
                      }}
                    />{" "}
                    <strong>{p.display_name}</strong>{" "}
                    <span className="muted">{p.confidence}</span>
                  </label>
                  <div className="muted">
                    {p.evidence.map((line, i) => (
                      <div key={i}>{line}</div>
                    ))}
                    {p.limitations.map((line, i) => (
                      <div key={`lim-${i}`}>{line}</div>
                    ))}
                  </div>
                </li>
              ))}
            </ul>
          </>
        )}

        {/* --- destinations read from the project (ADR 0024) ------------ */}
        {(requests.length > 0 || needsInput.length > 0 || originError) && (
          <>
            <h2>Destinations read from this project</h2>
            <p>
              These addresses came out of your project&apos;s own files, not from Tethra.
              Allowing one means this machine will forward requests — and the credential they
              carry — to that host. Each is a separate decision, and none is made by starting
              tracking.
            </p>
            {originError && (
              <p className="error" role="alert">
                The destinations could not be reviewed: {originError}
              </p>
            )}
            <ul className="stack" style={LIST_SCROLL}>
              {requests.map((r) => (
                <li key={r.provider_id}>
                  {r.refusal ? (
                    <>
                      <strong>{r.provider_display_name}</strong>{" "}
                      <span className="muted">{r.origin}</span>
                      <p className="error" role="alert">
                        {r.question} {r.refusal}
                      </p>
                    </>
                  ) : (
                    <>
                      <label>
                        <input
                          type="checkbox"
                          checked={r.approved_now}
                          onChange={(e) =>
                            void toggleOriginApproval(r.provider_id, r.origin, e.target.checked)
                          }
                        />{" "}
                        <strong>{r.host}</strong>{" "}
                        <span className="muted">
                          {r.provider_display_name} · {r.scheme}://{r.host}:{r.port}
                        </span>
                      </label>
                      <div className="muted">
                        <div>{r.question}</div>
                        {r.disclosure.map((line, i) => (
                          <div key={i}>{line}</div>
                        ))}
                        {r.previously_approved_at && (
                          <div>
                            You approved this exact destination on {r.previously_approved_at}.
                            It is still unchecked — approving it again is your decision, not a
                            memory.
                          </div>
                        )}
                      </div>
                    </>
                  )}
                </li>
              ))}
              {needsInput.map((p) => (
                <li key={p.provider_id}>
                  <div>
                    <strong>{p.display_name}</strong>{" "}
                    <span className="muted">
                      no destination could be read from this project
                    </span>
                  </div>
                  <div className="muted">
                    {p.evidence.map((line, i) => (
                      <div key={i}>{line}</div>
                    ))}
                  </div>
                  <div className="field">
                    <label htmlFor={`origin-${p.provider_id}`}>
                      Its project URL (traffic will be forwarded only to this exact address)
                    </label>
                    <input
                      id={`origin-${p.provider_id}`}
                      className="mono"
                      value={typedOrigins[p.provider_id] ?? ""}
                      placeholder="https://your-project.example.com"
                      onChange={(e) => {
                        setTypedOrigins({
                          ...typedOrigins,
                          [p.provider_id]: e.target.value,
                        });
                        // Editing the address withdraws any approval given
                        // for the previous one: approval is granted for one
                        // exact destination.
                        if (approvedTyped.has(p.provider_id)) {
                          void toggleTypedOrigin(p.provider_id, false);
                        }
                      }}
                    />
                  </div>
                  <label>
                    <input
                      type="checkbox"
                      disabled={(typedOrigins[p.provider_id] ?? "").trim().length === 0}
                      checked={approvedTyped.has(p.provider_id)}
                      onChange={(e) => void toggleTypedOrigin(p.provider_id, e.target.checked)}
                    />{" "}
                    Allow this project to send API traffic through this address
                  </label>
                </li>
              ))}
            </ul>
          </>
        )}

        {/* --- detected, not supported ---------------------------------- */}
        {unsupported.length > 0 && (
          <>
            <h2>Detected, but Tethra cannot observe them</h2>
            <ul className="stack" style={LIST_SCROLL}>
              {unsupported.map((p) => (
                <li key={p.provider_id}>
                  <div>
                    <strong>{p.display_name}</strong>{" "}
                    <span className="muted">detected, not currently supported</span>
                  </div>
                  <div className="muted">
                    {p.evidence.map((line, i) => (
                      <div key={i}>{line}</div>
                    ))}
                  </div>
                  <div>
                    <button
                      className="link"
                      onClick={() => toggleExpanded(`u-${p.provider_id}`)}
                    >
                      {expanded.has(`u-${p.provider_id}`) ? "Hide details" : "Review this API"}
                    </button>{" "}
                    <button
                      className="link"
                      onClick={() =>
                        void copyAction(
                          `manual setup for ${p.display_name}`,
                          manualInstruction(p, scan.folder),
                        )
                      }
                    >
                      Copy manual setup instructions
                    </button>
                    {onOpenAdvanced && (
                      <>
                        {" "}
                        <button className="link" onClick={onOpenAdvanced}>
                          Add a custom destination
                        </button>
                      </>
                    )}
                  </div>
                  {expanded.has(`u-${p.provider_id}`) && (
                    <div className="muted">
                      {p.unsupported_reason && <p>{p.unsupported_reason}</p>}
                      {p.limitations.map((line, i) => (
                        <p key={`lim-${i}`}>{line}</p>
                      ))}
                      <p>
                        Nothing about the rest of this setup is affected: the APIs above are
                        still configured, and this one is simply not observed.
                      </p>
                    </div>
                  )}
                </li>
              ))}
            </ul>
          </>
        )}

        {/* --- unrecognised credentials (ZFT-010) ----------------------- */}
        {scan.unrecognized.length > 0 && (
          <>
            <h2>Not recognised ({scan.unrecognized.length})</h2>
            <p>
              Tethra has no provider definition for these, so it does not know where their
              traffic goes and cannot track them. They are listed so this screen is not read as
              complete coverage. Only the variable name and the file are shown — never a value.
            </p>
            <ul style={LIST_SCROLL}>
              {scan.unrecognized.slice(0, UNRECOGNIZED_DISPLAY_LIMIT).map((u) => (
                <li key={`${u.file}:${u.var}`}>
                  <span className="mono">{u.var}</span>
                  {u.name_hint && (
                    <span className="muted"> — looks like {u.name_hint}</span>
                  )}{" "}
                  <span className="muted">in {u.file}</span>
                </li>
              ))}
            </ul>
            {scan.unrecognized.length > UNRECOGNIZED_DISPLAY_LIMIT && (
              <p className="muted">
                … and {scan.unrecognized.length - UNRECOGNIZED_DISPLAY_LIMIT} more, all counted
                in the {scan.unrecognized.length} above.
              </p>
            )}
          </>
        )}

        {(unsupported.length > 0 || scan.unrecognized.length > 0) && (
          <div>
            <button
              className="link"
              onClick={() =>
                void copyAction(
                  "provider support request",
                  supportRequestText(
                    unsupportedNames,
                    scan.folder,
                    unsupported.length === 0 ? "unrecognized" : "unsupported",
                  ),
                )
              }
            >
              Copy a provider-support request
            </button>
            {onOpenAdvanced && (
              <>
                {" "}
                <button className="link" onClick={onOpenAdvanced}>
                  Open advanced settings
                </button>
              </>
            )}
          </div>
        )}
        {copied && <p className="notice">Copied the {copied} to the clipboard.</p>}
        {copyFallback && (
          <div>
            <p className="muted">
              The clipboard is not available here. Select and copy this text:
            </p>
            <pre style={{ overflowX: "auto", background: "#f6f6f6", padding: "0.5rem" }}>
              {copyFallback}
            </pre>
          </div>
        )}

        <h2>Changes to your files</h2>
        {planError && (
          <p className="error" role="alert">
            The changes could not be prepared: {planError}
          </p>
        )}
        {!plan && !planError && selected.size > 0 && (
          <p className="muted">Preparing the diff…</p>
        )}
        {selected.size === 0 && (
          <p className="muted">Select at least one API above to see what would change.</p>
        )}
        <div style={LIST_SCROLL}>
          {plan?.files.map((f) => (
            <div key={f.path}>
              <p className="mono">
                {f.path} {f.exists ? "" : "(will be created)"} {f.changed ? "" : "— no change"}
              </p>
              {f.changed && (
                <pre style={{ overflowX: "auto", background: "#f6f6f6", padding: "0.5rem" }}>
                  {f.diff}
                </pre>
              )}
            </div>
          ))}
        </div>
        {plan && plan.warnings.length > 0 && (
          <div className="warnbox">
            {plan.warnings.map((w, i) => (
              <div key={i}>! {w}</div>
            ))}
          </div>
        )}

        <h2>Starting tracking will</h2>
        <ul>
          {plan?.service_actions.map((a, i) => (
            <li key={i}>{a}</li>
          ))}
          <li>
            run a local background service on 127.0.0.1 (starts at login; on macOS it appears in
            System Settings → Login Items)
          </li>
          <li>create the provider routes shown above and apply the file changes shown above</li>
          <li>
            record request metadata: provider, endpoint template, status, latency, sizes, and
            token counts and model names when responses carry them
          </li>
          <li>
            configure only the destinations you ticked above — starting tracking approves no
            destination on its own
          </li>
        </ul>
        <p>
          It will never record API keys, authorization headers, cookies, query values, prompts,
          request bodies, or response bodies. Only the project you selected is configured; local
          or remote traffic that bypasses Tethra is not observed.
        </p>
        <p className="muted">
          Note: any local program can send traffic to the loopback port; the service is a
          standing local relay to the providers listed above.
        </p>

        <div className="field">
          <label htmlFor="track-password">
            Label traffic with which stored credential was used (recommended)
          </label>
          <input
            id="track-password"
            type="password"
            placeholder="Master password — leave empty to skip"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {/* The ADR-0020 disclosure, identical in substance to the Advanced
              push-key dialog. Consent to a memory oracle must not be cheaper
              here than there just because this screen is the friendly one
              (ZFT-013). */}
          <small className="muted">
            This hands the local gateway a derived matching-only key so it can label observed
            traffic with which vault credential was used. The key cannot decrypt anything, but
            while it is resident, a process that can read the gateway&apos;s memory (or its
            database) gains an oracle for testing whether a value matches one of your
            credentials. It covers only credentials in linked, non-password-locked projects. The
            key is dropped when the service stops, when you revoke it, and when the vault locks
            (keep-while-locked defaults OFF; with it ON a locked vault keeps matching for at
            most your auto-lock duration, 8 h cap). You can enable this later from the
            dashboard. Tracking records traffic either way.
          </small>
        </div>

        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <div>
          <button disabled={!plan || busy} onClick={() => void startTracking()}>
            Start tracking
          </button>{" "}
          <button className="link" onClick={onDone}>
            Cancel
          </button>
        </div>
        {!plan && selected.size > 0 && !planError && (
          <p className="muted">Start tracking is disabled until the changes are prepared.</p>
        )}
        {selected.size === 0 && !nothingFound && (
          <p className="muted">
            Start tracking is disabled: nothing is selected, so there is nothing to configure.
          </p>
        )}
      </section>
    );
  }

  if (phase.name === "applying") {
    return (
      <section className="stack">
        <h1>Setting up tracking…</h1>
        <p className="muted">
          Installing the local service, creating routes, applying changes.
        </p>
      </section>
    );
  }

  if (phase.name === "waiting") {
    const report = phase.report;
    const watching = watchStopped === null;
    return (
      <section className="stack">
        <h1>Configuration applied</h1>
        <ul>
          {report.steps.map((s, i) => (
            <li key={i}>
              {s.outcome === "done" ? "✓" : s.outcome === "skipped" ? "•" : "✗"} {s.title}
              {s.detail && <span className="muted"> — {s.detail}</span>}
            </li>
          ))}
        </ul>
        {!report.attribution_enabled && (
          <p className="muted">
            Credential attribution is off — traffic is still recorded. You can enable it from
            the dashboard.
          </p>
        )}
        <h2>Almost done — one step left, in your project</h2>
        <p>
          {report.restart_expected
            ? "Restart your app, then make one API request."
            : "Make one API request from your app."}
        </p>
        {watching ? (
          <p className="muted">
            {waitedMs < RESTART_HINT_MS
              ? "Waiting for traffic…"
              : "Waiting for traffic… Tracking is not marked verified until a real request arrives."}
          </p>
        ) : (
          <p className="warnbox" role="status">
            {watchStopped}
          </p>
        )}
        {diagnoses && (
          <div>
            <h2>No traffic has reached Tethra yet. Most likely causes, checked in order:</h2>
            <ol>
              {diagnoses.map((d, i) => (
                <li key={i}>{d.message}</li>
              ))}
            </ol>
          </div>
        )}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <div>
          {!watching && <button onClick={checkAgain}>Check again</button>}{" "}
          <button
            disabled={diagnosing || !report.setup_id}
            onClick={() => report.setup_id && void runDiagnosis(report.setup_id)}
          >
            {diagnosing ? "Checking…" : "Run diagnostics"}
          </button>{" "}
          <button className="link" onClick={onDone}>
            Open dashboard
          </button>
        </div>
      </section>
    );
  }

  if (phase.name === "verified") {
    const status = phase.status;
    const unseen = status.providers.filter((p) => !p.last_observed_at);
    return (
      <section className="stack">
        <h1>Tracking verified</h1>
        <p>{status.health.sentence}</p>
        {status.observed_provider && (
          <p>
            Observed {status.observed_provider} from {status.folder}
            {status.observed_latency_ms !== null && ` (${status.observed_latency_ms} ms`}
            {status.observed_model && `, ${status.observed_model}`}
            {status.observed_latency_ms !== null && ")"}
          </p>
        )}
        {status.watch === "partial" && unseen.length > 0 && (
          <p className="muted">
            No {unseen.map((p) => p.provider_id).join(", ")} traffic observed yet — this is
            normal if the app hasn&apos;t called it. Tethra keeps watching.
          </p>
        )}
        <div>
          <button onClick={onDone}>Open dashboard</button>
        </div>
      </section>
    );
  }

  // attention
  const report = phase.report;
  const failed = report?.steps.find((s) => s.outcome === "failed");
  return (
    <section className="stack">
      <h1>Tracking is partially configured</h1>
      {report && (
        <ul>
          {report.steps.map((s, i) => (
            <li key={i}>
              {s.outcome === "done" ? "✓" : s.outcome === "skipped" ? "•" : "✗"} {s.title}
              {s.detail && <span className="muted"> — {s.detail}</span>}
            </li>
          ))}
        </ul>
      )}
      {failed && (
        <p className="error" role="alert">
          Setup stopped at “{failed.title}”: {failed.detail}. Completed steps are left in place.
        </p>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {report?.install_blocked && (
        <div className="warnbox">
          <p>macOS blocked the background service (this build is unsigned).</p>
          <button disabled={busy} onClick={() => void startForegroundFallback()}>
            Track while the app is open
          </button>
          <p className="muted">
            Tracking then runs only while Tethra is open — Tethra stops that helper when it
            quits. To allow the background service: System Settings → Privacy &amp; Security.
          </p>
        </div>
      )}
      <div>
        <button onClick={() => void pickFolder()}>Try again</button>{" "}
        <button className="link" onClick={onDone}>
          Back to dashboard
        </button>
      </div>
    </section>
  );
}
