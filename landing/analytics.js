(() => {
  "use strict";

  const measurementId = "G-MJQHJ6JT5Z";
  const consentKey = "tethra.analytics-consent.v1";
  const productionHosts = new Set([
    "usetethra.com",
    "www.usetethra.com",
    "usetethra.web.app",
    "usetethra.firebaseapp.com",
  ]);
  const collectionAllowed = location.protocol === "https:" && productionHosts.has(location.hostname);
  const pageType = document.body.dataset.page === "privacy" || document.body.dataset.page === "terms"
    ? document.body.dataset.page
    : "home";
  const safePageLocation = `https://usetethra.com/${pageType === "home" ? "" : pageType}`;
  const allowedEvents = new Set([
    "landing_session_start",
    "landing_section_view",
    "dmg_download_clicked",
    "navigation_clicked",
    "legal_document_opened",
    "analytics_consent_granted",
  ]);
  const allowedParameters = new Set(["page_type", "section", "source", "destination", "document"]);
  let configured = false;
  let scriptRequested = false;
  const seenSections = new Set();

  if (location.protocol === "file:") {
    document.querySelectorAll("[data-local-download]").forEach((link) => {
      link.setAttribute("href", link.dataset.localDownload);
    });
  }

  const readConsent = () => {
    try {
      const saved = localStorage.getItem(consentKey);
      return saved === "granted" || saved === "denied" ? saved : "unset";
    } catch {
      return "unset";
    }
  };

  const saveConsent = (choice) => {
    try {
      localStorage.setItem(consentKey, choice);
    } catch {
      // A blocked storage API leaves analytics disabled on the next visit.
    }
  };

  const disableAnalytics = (disabled) => {
    window[`ga-disable-${measurementId}`] = disabled;
  };

  const clearAnalyticsCookies = () => {
    document.cookie.split(";").forEach((cookie) => {
      const name = cookie.split("=")[0]?.trim();
      if (!name || (name !== "_ga" && !name.startsWith("_ga_"))) return;
      document.cookie = `${name}=; Max-Age=0; path=/; SameSite=Lax`;
    });
  };

  const configure = () => {
    if (configured || readConsent() !== "granted" || !collectionAllowed) return;
    configured = true;
    disableAnalytics(false);
    window.dataLayer = window.dataLayer || [];
    window.gtag = window.gtag || function gtag() { window.dataLayer.push(arguments); };
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
    window.gtag("config", measurementId, {
      send_page_view: false,
      allow_google_signals: false,
      allow_ad_personalization_signals: false,
      page_location: safePageLocation,
      page_referrer: "",
      page_title: `Tethra ${pageType}`,
    });

    if (!scriptRequested) {
      scriptRequested = true;
      const script = document.createElement("script");
      script.async = true;
      script.src = `https://www.googletagmanager.com/gtag/js?id=${measurementId}`;
      script.dataset.tethraAnalytics = "true";
      document.head.appendChild(script);
    }
  };

  const safeValue = (value) => typeof value === "string" && /^[a-z0-9_]{1,32}$/.test(value);
  const track = (name, parameters = {}) => {
    if (!allowedEvents.has(name) || readConsent() !== "granted" || !collectionAllowed) return;
    configure();
    if (!window.gtag) return;
    const payload = { page_type: pageType };
    Object.entries(parameters).forEach(([key, value]) => {
      if (allowedParameters.has(key) && safeValue(value)) payload[key] = value;
    });
    window.gtag("event", name, payload);
  };

  const banner = document.querySelector("[data-consent-banner]");
  const showBanner = () => {
    if (!(banner instanceof HTMLElement)) return;
    banner.hidden = false;
    document.body.classList.add("consent-open");
  };
  const hideBanner = () => {
    if (!(banner instanceof HTMLElement)) return;
    banner.hidden = true;
    document.body.classList.remove("consent-open");
  };

  const applyConsent = (choice) => {
    saveConsent(choice);
    if (choice === "granted") {
      configure();
      track("analytics_consent_granted", { source: "consent_banner" });
      track("landing_session_start");
    } else {
      disableAnalytics(true);
      window.gtag?.("consent", "update", {
        analytics_storage: "denied",
        ad_storage: "denied",
        ad_user_data: "denied",
        ad_personalization: "denied",
      });
      clearAnalyticsCookies();
    }
    hideBanner();
  };

  document.querySelectorAll("[data-consent]").forEach((button) => {
    button.addEventListener("click", () => applyConsent(button.dataset.consent));
  });
  document.querySelectorAll("[data-privacy-choices]").forEach((button) => {
    button.addEventListener("click", showBanner);
  });

  document.querySelectorAll("[data-download]").forEach((link) => {
    link.addEventListener("click", () => track("dmg_download_clicked", { source: link.dataset.download }));
  });
  document.querySelectorAll("[data-nav]").forEach((link) => {
    link.addEventListener("click", () => track("navigation_clicked", { destination: link.dataset.nav }));
  });
  document.querySelectorAll("[data-legal]").forEach((link) => {
    link.addEventListener("click", () => track("legal_document_opened", { document: link.dataset.legal }));
  });

  const sections = document.querySelectorAll("[data-section]");
  if (window.IntersectionObserver && sections.length > 0) {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          const section = entry.target.dataset.section;
          if (!entry.isIntersecting || !safeValue(section) || seenSections.has(section)) return;
          seenSections.add(section);
          track("landing_section_view", { section });
        });
      },
      { threshold: 0.45 },
    );
    sections.forEach((section) => observer.observe(section));
  }

  if (navigator.globalPrivacyControl === true && readConsent() === "unset") {
    saveConsent("denied");
  }

  if (readConsent() === "granted") {
    configure();
    track("landing_session_start");
  } else if (readConsent() === "unset") {
    showBanner();
  }
})();
