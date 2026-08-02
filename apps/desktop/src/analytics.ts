const MEASUREMENT_ID = "G-MJQHJ6JT5Z";
const CONSENT_KEY = "tethra.analytics-consent.v1";
const INVENTORY_STATE_KEY = "tethra.analytics-inventory.v1";
const CONSENT_EVENT = "tethra:analytics-consent";
const REGION_URL = "https://usetethra.com/region.json";
const REGION_TIMEOUT_MS = 4_000;
const MAX_INVENTORY_COUNT = 10_000_000;

export type AnalyticsConsent = "granted" | "denied" | "unset" | "resolving";

export type AnalyticsScreen =
  | "vault_setup"
  | "vault_unlock"
  | "dashboard"
  | "tracking_setup"
  | "projects"
  | "project_detail"
  | "project_form"
  | "credential_detail"
  | "credential_form"
  | "providers"
  | "provider_detail"
  | "repository_scan"
  | "env_files"
  | "destinations"
  | "sync_plans"
  | "rotation"
  | "temporary_access"
  | "alerts"
  | "notifications"
  | "usage"
  | "api_activity"
  | "gateway"
  | "pricing"
  | "templates"
  | "settings"
  | "backup";

export type DesktopProductEvent =
  | { name: "project_created" }
  | { name: "project_updated" }
  | { name: "project_archived" }
  | { name: "project_restored" }
  | {
      name: "credential_tracked";
      tracking_method: "stored_secret" | "reference" | "provider_test_key";
    }
  | { name: "credential_updated" }
  | { name: "credential_deleted" }
  | { name: "credential_validated" }
  | { name: "credential_copied" }
  | { name: "credential_revealed" }
  | { name: "credential_value_replaced" }
  | { name: "credential_provider_revoked" }
  | { name: "credentials_imported" }
  | { name: "project_tracking_configured" }
  | { name: "project_tracking_enabled" }
  | { name: "project_tracking_disabled" }
  | { name: "project_tracking_unlinked" }
  | { name: "tracking_setup_completed" }
  | { name: "template_applied" }
  | { name: "backup_created" }
  | { name: "backup_restored" }
  | { name: "credential_rotation_planned" }
  | { name: "credential_rotation_completed" };

export type DesktopAnalyticsEvent =
  | { name: "app_session_start" }
  | { name: "screen_view"; screen_name: AnalyticsScreen }
  | { name: "vault_unlocked" }
  | { name: "vault_locked" }
  | { name: "tracking_setup_started" }
  | { name: "settings_saved" }
  | { name: "analytics_consent_granted" }
  | { name: "legal_document_opened"; document: "privacy" | "terms" }
  | {
      name: "inventory_snapshot";
      project_count: number;
      credential_count: number;
      snapshot_reason: "session_start" | "inventory_changed";
    }
  | DesktopProductEvent;

declare global {
  interface Window {
    dataLayer?: unknown[][];
    gtag?: (...args: unknown[]) => void;
  }
}

let configured = false;
let scriptRequested = false;
let sessionReported = false;
let lastScreen: AnalyticsScreen | null = null;
let lastInventorySnapshot: string | null = null;
let initialization: Promise<AnalyticsConsent> | null = null;

interface InventoryState {
  project_count: number;
  credential_count: number;
}

function storageAvailable() {
  try {
    const probe = "__tethra_storage_probe__";
    localStorage.setItem(probe, probe);
    localStorage.removeItem(probe);
    return true;
  } catch {
    return false;
  }
}

function readStoredConsent(): Exclude<AnalyticsConsent, "resolving"> {
  if (!storageAvailable()) return "unset";
  const saved = localStorage.getItem(CONSENT_KEY);
  return saved === "granted" || saved === "denied" ? saved : "unset";
}

function validInventoryCount(value: unknown): value is number {
  return (
    Number.isSafeInteger(value) && Number(value) >= 0 && Number(value) <= MAX_INVENTORY_COUNT
  );
}

function readInventoryState(): InventoryState | null {
  if (!storageAvailable()) return null;
  try {
    const parsed = JSON.parse(localStorage.getItem(INVENTORY_STATE_KEY) ?? "null") as {
      project_count?: unknown;
      credential_count?: unknown;
    } | null;
    if (
      !parsed ||
      !validInventoryCount(parsed.project_count) ||
      !validInventoryCount(parsed.credential_count)
    ) {
      return null;
    }
    return {
      project_count: parsed.project_count,
      credential_count: parsed.credential_count,
    };
  } catch {
    return null;
  }
}

function writeInventoryState(state: InventoryState): boolean {
  if (!storageAvailable()) return false;
  try {
    localStorage.setItem(INVENTORY_STATE_KEY, JSON.stringify(state));
    return true;
  } catch {
    return false;
  }
}

const initialStoredConsent = readStoredConsent();
let effectiveConsent: AnalyticsConsent =
  initialStoredConsent === "unset" ? "resolving" : initialStoredConsent;

export function getAnalyticsConsent(): AnalyticsConsent {
  return effectiveConsent;
}

function broadcastConsent(consent: AnalyticsConsent) {
  window.dispatchEvent(new CustomEvent(CONSENT_EVENT, { detail: consent }));
}

function disableGoogleAnalytics(disabled: boolean) {
  (window as unknown as Record<string, boolean>)[`ga-disable-${MEASUREMENT_ID}`] = disabled;
}

function deleteAnalyticsCookies() {
  document.cookie.split(";").forEach((cookie) => {
    const name = cookie.split("=")[0]?.trim();
    if (!name || (name !== "_ga" && !name.startsWith("_ga_"))) return;
    document.cookie = `${name}=; Max-Age=0; path=/; SameSite=Lax`;
  });
}

function configureAnalytics() {
  if (configured || getAnalyticsConsent() !== "granted") return;
  configured = true;
  disableGoogleAnalytics(false);

  window.dataLayer = window.dataLayer ?? [];
  window.gtag =
    window.gtag ??
    ((...args: unknown[]) => {
      window.dataLayer?.push(args);
    });

  window.gtag("consent", "default", {
    analytics_storage: "denied",
    ad_storage: "denied",
    ad_user_data: "denied",
    ad_personalization: "denied",
  });
  window.gtag("consent", "update", {
    analytics_storage: "granted",
    ad_storage: "denied",
    ad_user_data: "denied",
    ad_personalization: "denied",
  });
  window.gtag("set", "ads_data_redaction", true);
  window.gtag("js", new Date());
  window.gtag("config", MEASUREMENT_ID, {
    send_page_view: false,
    allow_google_signals: false,
    allow_ad_personalization_signals: false,
    app_name: "Tethra Desktop",
    page_location: "https://usetethra.com/app",
    page_referrer: "",
    page_title: "Tethra Desktop",
  });

  if (!scriptRequested) {
    scriptRequested = true;
    const script = document.createElement("script");
    script.async = true;
    script.src = `https://www.googletagmanager.com/gtag/js?id=${MEASUREMENT_ID}`;
    script.dataset.tethraAnalytics = "true";
    document.head.appendChild(script);
  }
}

/**
 * Resolve the user's explicit choice first, then the hosting-provided country
 * default. A regional default is intentionally kept in memory rather than
 * stored as consent: moving outside the US on a later launch must not turn a
 * regional default into a durable affirmative choice.
 */
export function initializeAnalytics(): Promise<AnalyticsConsent> {
  if (initialization) return initialization;

  initialization = (async () => {
    const stored = readStoredConsent();
    const globalPrivacyControl = (navigator as Navigator & { globalPrivacyControl?: boolean })
      .globalPrivacyControl;

    if (globalPrivacyControl === true) {
      if (storageAvailable()) localStorage.setItem(CONSENT_KEY, "denied");
      effectiveConsent = "denied";
      disableGoogleAnalytics(true);
      deleteAnalyticsCookies();
      broadcastConsent(effectiveConsent);
      return effectiveConsent;
    }

    if (stored !== "unset") {
      effectiveConsent = stored;
      if (effectiveConsent === "granted") configureAnalytics();
      broadcastConsent(effectiveConsent);
      return effectiveConsent;
    }

    let useUsDefault = false;
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), REGION_TIMEOUT_MS);
    try {
      const response = await fetch(REGION_URL, {
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
        signal: controller.signal,
      });
      if (response.ok) {
        const region = (await response.json()) as {
          country?: unknown;
          analyticsDefault?: unknown;
        };
        useUsDefault = region.country === "US" && region.analyticsDefault === true;
      }
    } catch {
      // If region cannot be established, fall back to the consent request.
    } finally {
      window.clearTimeout(timeout);
    }

    effectiveConsent = useUsDefault ? "granted" : "unset";
    if (effectiveConsent === "granted") configureAnalytics();
    broadcastConsent(effectiveConsent);
    return effectiveConsent;
  })();

  return initialization;
}

export function setAnalyticsConsent(consent: Exclude<AnalyticsConsent, "unset" | "resolving">) {
  effectiveConsent = consent;
  if (storageAvailable()) localStorage.setItem(CONSENT_KEY, consent);

  if (consent === "granted") {
    configureAnalytics();
  } else {
    disableGoogleAnalytics(true);
    window.gtag?.("consent", "update", {
      analytics_storage: "denied",
      ad_storage: "denied",
      ad_user_data: "denied",
      ad_personalization: "denied",
    });
    deleteAnalyticsCookies();
    sessionReported = false;
    lastScreen = null;
    lastInventorySnapshot = null;
  }

  broadcastConsent(consent);
}

export function subscribeToAnalyticsConsent(listener: (consent: AnalyticsConsent) => void) {
  const handle = (event: Event) => {
    const detail = (event as CustomEvent<AnalyticsConsent>).detail;
    listener(detail);
  };
  window.addEventListener(CONSENT_EVENT, handle);
  return () => window.removeEventListener(CONSENT_EVENT, handle);
}

/**
 * Sends only compile-time enumerated events and parameters. Callers cannot
 * attach arbitrary vault, project, provider, path, URL, or request data.
 */
export function trackAnalytics(event: DesktopAnalyticsEvent) {
  if (getAnalyticsConsent() !== "granted") return;
  configureAnalytics();
  if (!window.gtag) return;

  if (event.name === "app_session_start") {
    if (sessionReported) return;
    sessionReported = true;
  }
  if (event.name === "screen_view") {
    if (lastScreen === event.screen_name) return;
    lastScreen = event.screen_name;
  }

  if (event.name === "inventory_snapshot") {
    if (
      !validInventoryCount(event.project_count) ||
      !validInventoryCount(event.credential_count)
    ) {
      return;
    }
    const fingerprint = `${event.project_count}:${event.credential_count}`;
    if (lastInventorySnapshot === fingerprint) return;
    lastInventorySnapshot = fingerprint;
  }

  const parameters: Record<string, string | number> = { app_surface: "desktop" };
  if (event.name === "screen_view") parameters.screen_name = event.screen_name;
  if (event.name === "legal_document_opened") parameters.document = event.document;
  if (event.name === "credential_tracked") parameters.tracking_method = event.tracking_method;
  if (event.name === "inventory_snapshot") {
    const previous = readInventoryState();
    parameters.project_count = event.project_count;
    parameters.credential_count = event.credential_count;
    parameters.snapshot_reason = event.snapshot_reason;

    if (previous) {
      parameters.snapshot_mode = "reconciled";
      parameters.project_count_delta = event.project_count - previous.project_count;
      parameters.credential_count_delta = event.credential_count - previous.credential_count;
    } else {
      // The first report from this app data store establishes its contribution
      // to the aggregate. No identifier, name, or vault record accompanies it.
      parameters.snapshot_mode = "baseline";
      parameters.project_count_delta = event.project_count;
      parameters.credential_count_delta = event.credential_count;
    }

    if (
      !writeInventoryState({
        project_count: event.project_count,
        credential_count: event.credential_count,
      })
    ) {
      // Without durable reconciliation state, sending deltas on every launch
      // would inflate the global estimate. Keep the useful absolute snapshot,
      // but deliberately omit unreliable delta fields.
      parameters.snapshot_mode = "unpersisted";
      delete parameters.project_count_delta;
      delete parameters.credential_count_delta;
    }
  }
  window.gtag("event", event.name, parameters);
}
