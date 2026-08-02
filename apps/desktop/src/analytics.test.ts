import { beforeEach, describe, expect, it, vi } from "vitest";

const measurementId = "G-MJQHJ6JT5Z";

beforeEach(() => {
  vi.resetModules();
  const values = new Map<string, string>();
  const storage: Storage = {
    get length() {
      return values.size;
    },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => Array.from(values.keys())[index] ?? null,
    removeItem: (key) => values.delete(key),
    setItem: (key, value) => values.set(key, String(value)),
  };
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: storage,
  });
  document
    .querySelectorAll("script[data-tethra-analytics]")
    .forEach((script) => script.remove());
  delete window.dataLayer;
  delete window.gtag;
  delete (window as unknown as Record<string, boolean>)[`ga-disable-${measurementId}`];
  Object.defineProperty(navigator, "globalPrivacyControl", {
    configurable: true,
    value: false,
  });
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ country: "OTHER", analyticsDefault: false }),
    }),
  );
});

describe("region-aware desktop analytics", () => {
  it("does not configure Google for an unresolved or non-US user before consent", async () => {
    const analytics = await import("./analytics");
    await analytics.initializeAnalytics();
    analytics.trackAnalytics({ name: "app_session_start" });

    expect(analytics.getAnalyticsConsent()).toBe("unset");
    expect(document.querySelector("script[data-tethra-analytics]")).toBeNull();
    expect(window.dataLayer).toBeUndefined();
  });

  it("enables the allowlisted stream by default for a US user without persisting consent", async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ country: "US", analyticsDefault: true }),
    } as Response);
    const analytics = await import("./analytics");

    await analytics.initializeAnalytics();
    analytics.trackAnalytics({ name: "app_session_start" });

    expect(analytics.getAnalyticsConsent()).toBe("granted");
    expect(localStorage.getItem("tethra.analytics-consent.v1")).toBeNull();
    expect(document.querySelector("script[data-tethra-analytics]")).not.toBeNull();
  });

  it("honors Global Privacy Control ahead of the US regional default", async () => {
    Object.defineProperty(navigator, "globalPrivacyControl", {
      configurable: true,
      value: true,
    });
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ country: "US", analyticsDefault: true }),
    } as Response);
    const analytics = await import("./analytics");

    await analytics.initializeAnalytics();

    expect(analytics.getAnalyticsConsent()).toBe("denied");
    expect(fetch).not.toHaveBeenCalled();
    expect(document.querySelector("script[data-tethra-analytics]")).toBeNull();
  });

  it("loads only the configured GA4 stream after an affirmative grant", async () => {
    const analytics = await import("./analytics");
    analytics.setAnalyticsConsent("granted");
    analytics.trackAnalytics({ name: "screen_view", screen_name: "dashboard" });

    const script = document.querySelector<HTMLScriptElement>("script[data-tethra-analytics]");
    expect(script?.src).toBe(`https://www.googletagmanager.com/gtag/js?id=${measurementId}`);
    expect(analytics.getAnalyticsConsent()).toBe("granted");
    expect(window.dataLayer).toEqual(
      expect.arrayContaining([
        ["event", "screen_view", { app_surface: "desktop", screen_name: "dashboard" }],
      ]),
    );
  });

  it("disables collection and drops later events after withdrawal", async () => {
    const analytics = await import("./analytics");
    analytics.setAnalyticsConsent("granted");
    analytics.trackAnalytics({ name: "app_session_start" });
    analytics.setAnalyticsConsent("denied");
    const queuedAtWithdrawal = window.dataLayer?.length;

    analytics.trackAnalytics({ name: "screen_view", screen_name: "settings" });

    expect(analytics.getAnalyticsConsent()).toBe("denied");
    expect((window as unknown as Record<string, boolean>)[`ga-disable-${measurementId}`]).toBe(
      true,
    );
    expect(window.dataLayer).toHaveLength(queuedAtWithdrawal ?? 0);
  });
});
