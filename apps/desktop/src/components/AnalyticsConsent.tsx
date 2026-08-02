import { useEffect, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
  getAnalyticsConsent,
  initializeAnalytics,
  setAnalyticsConsent,
  subscribeToAnalyticsConsent,
  trackAnalytics,
  type AnalyticsConsent as Consent,
} from "../analytics";

const LEGAL_URLS = {
  privacy: "https://usetethra.com/privacy",
  terms: "https://usetethra.com/terms",
} as const;

function LegalLink(props: { document: keyof typeof LEGAL_URLS; children: string }) {
  return (
    <button
      type="button"
      className="text-link"
      onClick={() => {
        trackAnalytics({ name: "legal_document_opened", document: props.document });
        void openUrl(LEGAL_URLS[props.document]);
      }}
    >
      {props.children}
    </button>
  );
}

function useConsent() {
  const [consent, setConsent] = useState<Consent>(() => getAnalyticsConsent());
  useEffect(() => {
    const unsubscribe = subscribeToAnalyticsConsent(setConsent);
    void initializeAnalytics().then(setConsent);
    return unsubscribe;
  }, []);
  return consent;
}

export function AnalyticsConsentBanner() {
  const consent = useConsent();
  if (consent !== "unset") return null;

  return (
    <aside className="consent-banner" aria-labelledby="analytics-consent-title">
      <div>
        <p className="consent-kicker">Optional analytics</p>
        <h2 id="analytics-consent-title">Help improve Tethra</h2>
        <p>
          With your permission, Google Analytics records broad screen use and app sessions. It
          never receives credentials, project names, file paths, provider names, URLs, request
          content, or vault data. Nothing is sent unless you choose Allow.
        </p>
        <p className="consent-links">
          <LegalLink document="privacy">Privacy policy</LegalLink>
          <LegalLink document="terms">Terms</LegalLink>
        </p>
      </div>
      <div className="consent-actions">
        <button
          type="button"
          className="secondary"
          onClick={() => setAnalyticsConsent("denied")}
        >
          Not now
        </button>
        <button
          type="button"
          onClick={() => {
            setAnalyticsConsent("granted");
            trackAnalytics({ name: "analytics_consent_granted" });
          }}
        >
          Allow analytics
        </button>
      </div>
    </aside>
  );
}

export function AnalyticsPreferences() {
  const consent = useConsent();
  const enabled = consent === "granted";
  const resolving = consent === "resolving";

  return (
    <section
      className="settings-section analytics-preferences"
      aria-labelledby="analytics-heading"
    >
      <div className="settings-section-heading">
        <div>
          <p className="screen-kicker">Privacy</p>
          <h2 id="analytics-heading">Pseudonymous product analytics</h2>
        </div>
        <label className="switch-control">
          <input
            type="checkbox"
            checked={enabled}
            disabled={resolving}
            onChange={(event) => {
              const next = event.target.checked ? "granted" : "denied";
              setAnalyticsConsent(next);
              if (next === "granted") trackAnalytics({ name: "analytics_consent_granted" });
            }}
          />
          <span aria-hidden="true" />
          <b>{resolving ? "Checking" : enabled ? "Allowed" : "Off"}</b>
        </label>
      </div>
      <p className="muted">
        Measurement analytics is on by default for users in the United States unless Global
        Privacy Control or a prior opt-out applies; elsewhere Tethra asks before enabling it.
        The allowlisted events exclude vault contents and free-form values. Turning this off
        stops future collection and clears accessible Analytics cookies.
      </p>
      <p className="consent-links">
        <LegalLink document="privacy">Read privacy policy</LegalLink>
        <LegalLink document="terms">Read terms</LegalLink>
      </p>
    </section>
  );
}
