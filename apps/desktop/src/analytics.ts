const MEASUREMENT_ID = "G-MJQHJ6JT5Z";
const CONSENT_KEY = "tethra.analytics-consent.v1";
const CONSENT_EVENT = "tethra:analytics-consent";

export type AnalyticsConsent = "granted" | "denied" | "unset";

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

export type DesktopAnalyticsEvent =
  | { name: "app_session_start" }
  | { name: "screen_view"; screen_name: AnalyticsScreen }
  | { name: "vault_unlocked" }
  | { name: "vault_locked" }
  | { name: "tracking_setup_started" }
  | { name: "settings_saved" }
  | { name: "analytics_consent_granted" }
  | { name: "legal_document_opened"; document: "privacy" | "terms" };

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

export function getAnalyticsConsent(): AnalyticsConsent {
  if (!storageAvailable()) return "unset";
  const saved = localStorage.getItem(CONSENT_KEY);
  return saved === "granted" || saved === "denied" ? saved : "unset";
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

export function initializeAnalytics() {
  if (getAnalyticsConsent() === "granted") configureAnalytics();
}

export function setAnalyticsConsent(consent: Exclude<AnalyticsConsent, "unset">) {
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
  }

  window.dispatchEvent(new CustomEvent(CONSENT_EVENT, { detail: consent }));
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

  const parameters: Record<string, string> = { app_surface: "desktop" };
  if (event.name === "screen_view") parameters.screen_name = event.screen_name;
  if (event.name === "legal_document_opened") parameters.document = event.document;
  window.gtag("event", event.name, parameters);
}
