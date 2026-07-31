// The ONE refresh mechanism for live local data (ADR 0029).
//
// One timer, shared by every card and chart on a surface. Not one timer per
// component: N timers on a page means N concurrent backend calls per tick, N
// independent backoffs, and N chances to leave one running after unmount.
//
// What this guarantees, and why each one is here:
//
//   * No overlap. A tick that arrives while a fetch is in flight is dropped,
//     not queued. Queuing turns a slow backend into an unbounded backlog that
//     keeps firing after the user has left.
//   * No stale overwrite. Every fetch carries a sequence number and a result
//     is discarded if a newer fetch has already started. Without this, a slow
//     response can land after a fast one and roll the display backwards —
//     which on a live view looks exactly like real data arriving.
//   * Backoff on failure, reset on success. A gateway that is down, or a
//     database that is busy, must not be polled every five seconds forever.
//   * Slow down when hidden, refresh on focus. A hidden window has no reader.
//   * Nothing runs after unmount. The timer is cleared and in-flight results
//     are ignored, so no setState fires on an unmounted component.
//
// Deliberately NOT here: any provider API call. This polls local observations
// Tethra already recorded. Provider-side usage synchronisation keeps its own
// much slower cadence and its own rate limits.

import { useCallback, useEffect, useRef, useState } from "react";

/** How often a visible, healthy surface refreshes. */
export const VISIBLE_INTERVAL_MS = 5_000;

/** How often a hidden surface refreshes. */
export const HIDDEN_INTERVAL_MS = 60_000;

/** First delay after a failure, doubled per consecutive failure. */
export const BACKOFF_BASE_MS = 5_000;

/** Ceiling on the backoff, so a long outage still recovers within a minute. */
export const BACKOFF_MAX_MS = 60_000;

export interface LiveRefreshState<T> {
  /** The most recent successful payload, or null before the first one. */
  data: T | null;
  /** True only while the FIRST load is in flight; later ticks refresh in place
   *  so a live view does not flash a spinner every five seconds. */
  loading: boolean;
  /** True while any fetch is in flight, for a subtle activity indicator. */
  refreshing: boolean;
  /** The last error, kept alongside `data` so a failed refresh does not blank
   *  a display that still holds the last good answer. */
  error: string | null;
  /** When the last SUCCESSFUL refresh completed, as an ISO string. */
  lastSuccessAt: string | null;
  /** Consecutive failures; > 0 means the interval is backed off. */
  failures: number;
  /** Force a refresh now. Returns false when one was already in flight. */
  refresh: () => Promise<boolean>;
}

/**
 * Poll `fetcher` while mounted.
 *
 * `fetcher` must be stable (wrap it in `useCallback`); changing it restarts the
 * loop and refetches, which is what a changed project id or time range should
 * do.
 *
 * `enabled: false` stops polling without unmounting — used while the vault is
 * locked, where every call would fail anyway.
 */
export function useLiveRefresh<T>(
  fetcher: () => Promise<T>,
  options: { enabled?: boolean; intervalMs?: number } = {},
): LiveRefreshState<T> {
  const { enabled = true, intervalMs = VISIBLE_INTERVAL_MS } = options;

  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastSuccessAt, setLastSuccessAt] = useState<string | null>(null);
  const [failures, setFailures] = useState(0);

  // Refs, not state: these coordinate the loop and must not re-render it.
  const inFlight = useRef(false);
  const sequence = useRef(0);
  const applied = useRef(0);
  const mounted = useRef(true);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const failuresRef = useRef(0);
  const hidden = useRef(
    typeof document !== "undefined" && document.visibilityState === "hidden",
  );
  /**
   * Which incarnation of the loop is live.
   *
   * Bumped whenever the fetcher identity or `enabled` changes. Every closure
   * captures the generation it was created in and no-ops if it is no longer
   * current. Without this, changing the time range while a fetch was in flight
   * left the OLD fetch's `.finally(() => schedule())` to arm a timer over the
   * OLD fetcher — and because `inFlight` is shared, the new incarnation's first
   * fetch was ALSO dropped by the overlap guard. The result was a loop
   * permanently polling the range the user had just navigated away from.
   */
  const generation = useRef(0);
  const enabledRef = useRef(enabled);
  enabledRef.current = enabled;

  const clearTimer = useCallback(() => {
    if (timer.current !== null) {
      clearTimeout(timer.current);
      timer.current = null;
    }
  }, []);

  const runFetch = useCallback(async (): Promise<boolean> => {
    // Overlap guard. Dropping the tick is correct: the in-flight fetch is
    // already going to deliver fresher data than this tick could.
    if (inFlight.current || !mounted.current) return false;
    const gen = generation.current;
    inFlight.current = true;
    const seq = ++sequence.current;
    setRefreshing(true);
    try {
      const next = await fetcher();
      // Stale-response guard. `applied` only ever moves forward, so a slow
      // response that lost the race cannot roll the display backwards, and a
      // result from a superseded generation is discarded outright.
      if (mounted.current && gen === generation.current && seq > applied.current) {
        applied.current = seq;
        setData(next);
        setError(null);
        setLastSuccessAt(new Date().toISOString());
        failuresRef.current = 0;
        setFailures(0);
      }
      return true;
    } catch (e) {
      if (mounted.current && gen === generation.current && seq > applied.current) {
        // The error is recorded but `data` is left alone: a failed refresh
        // must not blank a display that still holds the last good answer.
        setError(errorText(e));
        failuresRef.current += 1;
        setFailures(failuresRef.current);
      }
      return false;
    } finally {
      inFlight.current = false;
      if (mounted.current) {
        setRefreshing(false);
        setLoading(false);
      }
    }
  }, [fetcher]);

  /** The delay before the next tick, given health and visibility. */
  const nextDelay = useCallback(() => {
    if (failuresRef.current > 0) {
      const grown = BACKOFF_BASE_MS * 2 ** (failuresRef.current - 1);
      return Math.min(grown, BACKOFF_MAX_MS);
    }
    return hidden.current ? HIDDEN_INTERVAL_MS : intervalMs;
  }, [intervalMs]);

  // A self-rescheduling timeout rather than setInterval: the delay changes with
  // health and visibility, and setInterval cannot express that without being
  // torn down and rebuilt on every change.
  const schedule = useCallback(() => {
    // A stale incarnation must not arm anything, or it re-establishes itself
    // after the current one has already scheduled its own tick.
    const gen = generation.current;
    clearTimer();
    // `enabledRef`, not the captured `enabled`: a closure created while enabled
    // and invoked from a pending `.finally()` after it was disabled would
    // otherwise happily arm the next tick.
    if (!mounted.current || !enabledRef.current) return;
    timer.current = setTimeout(() => {
      if (gen !== generation.current) return;
      void runFetch().finally(() => {
        if (gen === generation.current) schedule();
      });
    }, nextDelay());
  }, [clearTimer, nextDelay, runFetch]);

  const refresh = useCallback(async () => {
    const ok = await runFetch();
    // Re-arm from now, so a manual refresh does not leave a tick about to fire
    // immediately afterwards.
    schedule();
    return ok;
  }, [runFetch, schedule]);

  useEffect(() => {
    mounted.current = true;
    // A new incarnation. Anything the previous one has pending is now stale,
    // including its in-flight fetch — so release the overlap guard too, or this
    // incarnation's first fetch is dropped and the loop never starts.
    generation.current += 1;
    inFlight.current = false;
    if (!enabled) {
      clearTimer();
      // `loading` starts true and is otherwise only cleared in `runFetch`'s
      // finally — which never runs while disabled. Leaving it set stranded the
      // surface on "Loading…" indefinitely for, say, an archived project.
      setLoading(false);
      // The disabled branch STILL has to clear `mounted` on unmount. Returning a
      // cleanup that only stops the timer left the mounted guard armed, so a
      // late result from a previously-leaked fetch could set state after the
      // component was gone.
      return () => {
        mounted.current = false;
        clearTimer();
      };
    }
    const gen = generation.current;
    // Refresh immediately when the surface opens, then settle into the loop.
    void runFetch().finally(() => {
      if (gen === generation.current) schedule();
    });
    return () => {
      // Unmount cleanup: stop the timer AND stop any in-flight result from
      // being applied, so nothing sets state on an unmounted component.
      mounted.current = false;
      clearTimer();
    };
  }, [enabled, runFetch, schedule, clearTimer]);

  // Visibility and focus. A hidden window slows down; regaining focus
  // refreshes at once, because the user is looking at possibly-stale numbers.
  useEffect(() => {
    if (!enabled) return;
    const onVisibility = () => {
      hidden.current = document.visibilityState === "hidden";
      if (!hidden.current) {
        void runFetch().finally(() => schedule());
      } else {
        schedule();
      }
    };
    const onFocus = () => {
      // A focused window is a visible one; without this the cadence could stay
      // on the hidden interval after the user came back.
      hidden.current = false;
      void runFetch().finally(() => schedule());
    };
    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("focus", onFocus);
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("focus", onFocus);
    };
  }, [enabled, runFetch, schedule]);

  return {
    data,
    loading,
    refreshing,
    error,
    lastSuccessAt,
    failures,
    refresh,
  };
}

/** Backend errors arrive as `{ code, message }`; anything else is stringified. */
function errorText(e: unknown): string {
  if (e && typeof e === "object" && "message" in e) {
    const m = (e as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return String(e);
}

/** "8 seconds ago" for a "last updated" line. Whole units only. */
export function relativeTime(iso: string | null, now: number = Date.now()): string {
  if (!iso) return "never";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "unknown";
  const seconds = Math.max(0, Math.round((now - then) / 1000));
  if (seconds < 1) return "just now";
  if (seconds === 1) return "1 second ago";
  if (seconds < 60) return `${seconds} seconds ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes === 1) return "1 minute ago";
  if (minutes < 60) return `${minutes} minutes ago`;
  const hours = Math.round(minutes / 60);
  if (hours === 1) return "1 hour ago";
  if (hours < 24) return `${hours} hours ago`;
  const days = Math.round(hours / 24);
  return days === 1 ? "1 day ago" : `${days} days ago`;
}
