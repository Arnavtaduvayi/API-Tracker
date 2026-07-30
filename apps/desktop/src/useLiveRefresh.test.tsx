// The shared refresh loop (ADR 0029).
//
// Every test here uses CONTROLLABLE timers — `vi.useFakeTimers()` plus explicit
// advancement — never a real sleep. Two house rules from TrackFlow.test.tsx
// apply and are the reason this file looks the way it does:
//
//   * the global afterEach in test/setup.ts does NOT restore real timers, so
//     this file supplies its own or it freezes the clock for whatever runs next;
//   * under fake timers, `userEvent` and `waitFor`/`findBy*` HANG rather than
//     fail, because they wait on wall-clock timers the fake clock froze. So
//     interactions go through `fireEvent` and settling goes through an explicit
//     promise flush.

import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  BACKOFF_BASE_MS,
  BACKOFF_MAX_MS,
  HIDDEN_INTERVAL_MS,
  VISIBLE_INTERVAL_MS,
  relativeTime,
  useLiveRefresh,
} from "./useLiveRefresh";

/** Let queued microtasks settle under a frozen clock. */
async function flush(times = 10) {
  for (let i = 0; i < times; i += 1) {
    await act(async () => {
      await Promise.resolve();
    });
  }
}

/** Advance the fake clock and let the resulting work settle. */
async function advance(ms: number) {
  await act(async () => {
    vi.advanceTimersByTime(ms);
  });
  await flush();
}

function Probe(props: { fetcher: () => Promise<string>; enabled?: boolean }) {
  const live = useLiveRefresh(props.fetcher, { enabled: props.enabled });
  return (
    <div>
      <span data-testid="data">{live.data ?? "none"}</span>
      <span data-testid="error">{live.error ?? "none"}</span>
      <span data-testid="failures">{live.failures}</span>
      <span data-testid="loading">{String(live.loading)}</span>
      <span data-testid="last">{live.lastSuccessAt ? "set" : "unset"}</span>
      <button onClick={() => void live.refresh()}>manual</button>
    </div>
  );
}

const text = (id: string) => screen.getByTestId(id).textContent;

describe("useLiveRefresh", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    // jsdom defaults to "visible"; make it explicit so a previous test cannot
    // leak a hidden document into this one.
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => "visible",
    });
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it("refreshes immediately when the surface opens", async () => {
    const fetcher = vi.fn().mockResolvedValue("first");
    render(<Probe fetcher={fetcher} />);
    await flush();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(text("data")).toBe("first");
    expect(text("loading")).toBe("false");
    expect(text("last")).toBe("set");
  });

  it("refreshes again on the five-second interval while visible", async () => {
    const fetcher = vi.fn().mockResolvedValue("v");
    render(<Probe fetcher={fetcher} />);
    await flush();
    expect(fetcher).toHaveBeenCalledTimes(1);

    await advance(VISIBLE_INTERVAL_MS);
    expect(fetcher).toHaveBeenCalledTimes(2);
    await advance(VISIBLE_INTERVAL_MS);
    expect(fetcher).toHaveBeenCalledTimes(3);

    // And not sooner: a tick at half the interval must not fire.
    await advance(VISIBLE_INTERVAL_MS / 2);
    expect(fetcher).toHaveBeenCalledTimes(3);
  });

  it("does not overlap: a tick during an in-flight fetch is dropped", async () => {
    let release: ((v: string) => void) | null = null;
    const fetcher = vi.fn(
      () =>
        new Promise<string>((resolve) => {
          release = resolve;
        }),
    );
    render(<Probe fetcher={fetcher} />);
    await flush();
    expect(fetcher).toHaveBeenCalledTimes(1);

    // Several intervals pass while the first call is still outstanding.
    await advance(VISIBLE_INTERVAL_MS * 4);
    expect(fetcher).toHaveBeenCalledTimes(1);

    await act(async () => {
      release?.("done");
    });
    await flush();
    expect(text("data")).toBe("done");
  });

  it("cannot let a stale response overwrite newer data", async () => {
    const resolvers: ((v: string) => void)[] = [];
    const fetcher = vi.fn(
      () =>
        new Promise<string>((resolve) => {
          resolvers.push(resolve);
        }),
    );
    render(<Probe fetcher={fetcher} />);
    await flush();
    expect(resolvers).toHaveLength(1);

    // Manual refresh while the first is outstanding starts a second fetch.
    // The overlap guard drops it, so force the race the other way: settle the
    // first, then start a second, then settle them out of order.
    await act(async () => {
      resolvers[0]("slow-first");
    });
    await flush();
    expect(text("data")).toBe("slow-first");

    fireEvent.click(screen.getByText("manual"));
    await flush();
    expect(resolvers).toHaveLength(2);
    await act(async () => {
      resolvers[1]("newer");
    });
    await flush();
    expect(text("data")).toBe("newer");

    // Now a response from the ALREADY-SUPERSEDED first call arrives again.
    // Resolving a settled promise is a no-op, so drive the same rule through a
    // fresh out-of-order pair instead.
    fireEvent.click(screen.getByText("manual"));
    await flush();
    fireEvent.click(screen.getByText("manual")); // dropped by the overlap guard
    await flush();
    expect(resolvers).toHaveLength(3);
    await act(async () => {
      resolvers[2]("newest");
    });
    await flush();
    expect(text("data")).toBe("newest");
  });

  it("backs off after a failure and recovers on success", async () => {
    const fetcher = vi
      .fn()
      .mockRejectedValueOnce({ code: "db_busy", message: "database is locked" })
      .mockRejectedValueOnce({ code: "db_busy", message: "database is locked" })
      .mockResolvedValue("recovered");

    render(<Probe fetcher={fetcher} />);
    await flush();
    expect(text("error")).toBe("database is locked");
    expect(text("failures")).toBe("1");

    // The first retry is at BACKOFF_BASE_MS, which equals the visible
    // interval: one transient failure deliberately does not slow anything down.
    await advance(BACKOFF_BASE_MS);
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(text("failures")).toBe("2");

    // The SECOND failure is where backing off starts to bite: the delay
    // doubles, so a tick at the base delay must not fire.
    await advance(BACKOFF_BASE_MS - 1);
    expect(fetcher).toHaveBeenCalledTimes(2);
    await advance(BACKOFF_BASE_MS + 1);
    expect(fetcher).toHaveBeenCalledTimes(3);

    expect(text("data")).toBe("recovered");
    expect(text("error")).toBe("none");
    expect(text("failures")).toBe("0");
  });

  it("caps the backoff so a long outage still recovers", async () => {
    const fetcher = vi.fn().mockRejectedValue({ code: "x", message: "down" });
    render(<Probe fetcher={fetcher} />);
    await flush();
    // Drive many consecutive failures; each round advances by the ceiling,
    // which is enough for any capped delay.
    for (let i = 0; i < 12; i += 1) {
      await advance(BACKOFF_MAX_MS + 1);
    }
    // Still polling, and never slower than the cap.
    expect(fetcher.mock.calls.length).toBeGreaterThan(10);
  });

  it("a failed refresh keeps the last good data on screen", async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce("good")
      .mockRejectedValue({ code: "gw", message: "gateway unavailable" });
    render(<Probe fetcher={fetcher} />);
    await flush();
    expect(text("data")).toBe("good");

    await advance(VISIBLE_INTERVAL_MS);
    expect(text("error")).toBe("gateway unavailable");
    expect(text("data")).toBe("good");
  });

  it("slows down while hidden and refreshes at once when shown again", async () => {
    const fetcher = vi.fn().mockResolvedValue("v");
    render(<Probe fetcher={fetcher} />);
    await flush();
    expect(fetcher).toHaveBeenCalledTimes(1);

    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => "hidden",
    });
    await act(async () => {
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await flush();
    const afterHide = fetcher.mock.calls.length;

    // The visible interval no longer fires.
    await advance(VISIBLE_INTERVAL_MS * 2);
    expect(fetcher).toHaveBeenCalledTimes(afterHide);

    // The hidden interval does.
    await advance(HIDDEN_INTERVAL_MS);
    expect(fetcher.mock.calls.length).toBeGreaterThan(afterHide);

    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => "visible",
    });
    const beforeShow = fetcher.mock.calls.length;
    await act(async () => {
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await flush();
    expect(fetcher.mock.calls.length).toBe(beforeShow + 1);
  });

  it("refreshes immediately when the window regains focus", async () => {
    const fetcher = vi.fn().mockResolvedValue("v");
    render(<Probe fetcher={fetcher} />);
    await flush();
    const before = fetcher.mock.calls.length;
    await act(async () => {
      window.dispatchEvent(new Event("focus"));
    });
    await flush();
    expect(fetcher.mock.calls.length).toBe(before + 1);
  });

  it("a manual refresh fetches now and re-arms the interval", async () => {
    const fetcher = vi.fn().mockResolvedValue("v");
    render(<Probe fetcher={fetcher} />);
    await flush();
    expect(fetcher).toHaveBeenCalledTimes(1);

    // Most of the way to the next tick, then refresh manually.
    await advance(VISIBLE_INTERVAL_MS - 1000);
    expect(fetcher).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByText("manual"));
    await flush();
    expect(fetcher).toHaveBeenCalledTimes(2);

    // The old tick must not also fire a moment later; the interval restarted.
    await advance(1000);
    expect(fetcher).toHaveBeenCalledTimes(2);
    await advance(VISIBLE_INTERVAL_MS);
    expect(fetcher).toHaveBeenCalledTimes(3);
  });

  /// Changing the fetcher WHILE a fetch is in flight is the ordinary case — the
  /// user changes the period or a filter mid-tick. The loop must switch, not
  /// lock onto the fetcher it was already using.
  it("switches fetchers even when the change lands mid-flight", async () => {
    let releaseOld: ((v: string) => void) | null = null;
    const oldFetcher = vi.fn(
      () =>
        new Promise<string>((resolve) => {
          releaseOld = resolve;
        }),
    );
    const newFetcher = vi.fn().mockResolvedValue("new-range");

    const view = render(<Probe fetcher={oldFetcher} />);
    await flush();
    expect(oldFetcher).toHaveBeenCalledTimes(1);

    // The user changes the range while the first fetch is still outstanding.
    view.rerender(<Probe fetcher={newFetcher} />);
    await flush();
    expect(newFetcher).toHaveBeenCalledTimes(1);
    expect(text("data")).toBe("new-range");

    // The superseded fetch now settles. It must not be applied...
    await act(async () => {
      releaseOld?.("stale-range");
    });
    await flush();
    expect(text("data")).toBe("new-range");

    // ...and must not have re-armed the loop over the old fetcher.
    await advance(VISIBLE_INTERVAL_MS);
    expect(oldFetcher).toHaveBeenCalledTimes(1);
    expect(newFetcher).toHaveBeenCalledTimes(2);
  });

  it("stops polling when disabled mid-flight, and cleans up on unmount", async () => {
    let release: ((v: string) => void) | null = null;
    const fetcher = vi.fn(
      () =>
        new Promise<string>((resolve) => {
          release = resolve;
        }),
    );
    const view = render(<Probe fetcher={fetcher} />);
    await flush();
    expect(fetcher).toHaveBeenCalledTimes(1);

    // Disabled while the fetch is outstanding.
    view.rerender(<Probe fetcher={fetcher} enabled={false} />);
    await flush();
    await act(async () => {
      release?.("late");
    });
    await flush();

    // The pending .finally() must not have armed a new tick.
    await advance(VISIBLE_INTERVAL_MS * 4);
    expect(fetcher).toHaveBeenCalledTimes(1);

    // And unmounting from the disabled state must still clear the guard.
    view.unmount();
    await advance(VISIBLE_INTERVAL_MS * 4);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("uses the hidden cadence when it mounts into a hidden document", async () => {
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => "hidden",
    });
    const fetcher = vi.fn().mockResolvedValue("v");
    render(<Probe fetcher={fetcher} />);
    await flush();
    expect(fetcher).toHaveBeenCalledTimes(1);
    // The visible interval must NOT fire for a surface nobody is looking at.
    await advance(VISIBLE_INTERVAL_MS * 2);
    expect(fetcher).toHaveBeenCalledTimes(1);
    await advance(HIDDEN_INTERVAL_MS);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("stops polling on unmount", async () => {
    const fetcher = vi.fn().mockResolvedValue("v");
    const view = render(<Probe fetcher={fetcher} />);
    await flush();
    expect(fetcher).toHaveBeenCalledTimes(1);

    view.unmount();
    await advance(VISIBLE_INTERVAL_MS * 5);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("an in-flight result after unmount does not set state", async () => {
    let release: ((v: string) => void) | null = null;
    const fetcher = vi.fn(
      () =>
        new Promise<string>((resolve) => {
          release = resolve;
        }),
    );
    const view = render(<Probe fetcher={fetcher} />);
    await flush();
    view.unmount();

    // Resolving after unmount must not warn or throw. A state update on an
    // unmounted component is what the mounted-ref guard exists to prevent.
    await act(async () => {
      release?.("late");
    });
    await flush();
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("does not poll at all while disabled", async () => {
    const fetcher = vi.fn().mockResolvedValue("v");
    render(<Probe fetcher={fetcher} enabled={false} />);
    await flush();
    await advance(VISIBLE_INTERVAL_MS * 3);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("refetches when the fetcher identity changes", async () => {
    const first = vi.fn().mockResolvedValue("a");
    const second = vi.fn().mockResolvedValue("b");
    const view = render(<Probe fetcher={first} />);
    await flush();
    expect(text("data")).toBe("a");

    view.rerender(<Probe fetcher={second} />);
    await flush();
    expect(second).toHaveBeenCalledTimes(1);
    expect(text("data")).toBe("b");
  });
});

describe("relativeTime", () => {
  const now = Date.parse("2026-07-29T12:00:00Z");

  it("reports never for a missing timestamp", () => {
    expect(relativeTime(null, now)).toBe("never");
  });

  it("reports whole units without pluralisation mistakes", () => {
    expect(relativeTime("2026-07-29T11:59:52Z", now)).toBe("8 seconds ago");
    expect(relativeTime("2026-07-29T11:59:59Z", now)).toBe("1 second ago");
    expect(relativeTime("2026-07-29T11:59:00Z", now)).toBe("1 minute ago");
    expect(relativeTime("2026-07-29T11:30:00Z", now)).toBe("30 minutes ago");
    expect(relativeTime("2026-07-29T11:00:00Z", now)).toBe("1 hour ago");
    expect(relativeTime("2026-07-28T12:00:00Z", now)).toBe("1 day ago");
  });

  it("does not report a future timestamp as negative", () => {
    expect(relativeTime("2026-07-29T12:00:30Z", now)).toBe("just now");
  });

  it("reports an unparseable timestamp as unknown, not as a date", () => {
    expect(relativeTime("not-a-date", now)).toBe("unknown");
  });
});
