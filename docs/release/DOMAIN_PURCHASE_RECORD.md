# Domain Purchase Record — UseTethra.com

- **Exact domain:** `usetethra.com` (brand styling: UseTethra.com)
- **Status:** **PURCHASED BY THE USER DIRECTLY** on 2026-07-24 (the earlier
  agent-mediated attempt the same day was blocked — original record below).
- **Registrar:** Squarespace Domains LLC
- **Registered (registry Creation Date):** 2026-07-24T15:43:24Z
- **Expiration (Registry Expiry Date):** 2027-07-24T15:43:24Z (one-year
  registration, as planned)
- **Nameservers:** NSB1–NSB4.SQUARESPACEDNS.COM (registrar defaults)
- **Registry status:** clientDeleteProhibited, clientTransferProhibited
  (standard new-registration locks)
- **Verified:** via authoritative Verisign whois + RDAP on 2026-07-24,
  read-only. No agent payment was involved; no card details exist to record.
- **First-year price paid:** $14 (user-reported, paid directly by the user)
- **Renewal price displayed:** $20/year (user-reported)
- **Auto-renew:** user's intent is OFF (user-reported; account-side toggle
  managed by the user in Squarespace — not verified by the agent)
- **WHOIS privacy:** ACTIVE at no extra charge (verified via public whois:
  registrant "REDACTED FOR PRIVACY")
- **Order number:** not recorded (not available to the user at the time of
  writing; the receipt lives in the user's Squarespace account email)
- **Current DNS / website (verified 2026-08-01):** the apex resolves to
  Firebase Hosting at `199.36.158.100`; `https://usetethra.com`, `/privacy`,
  and `/terms` return the deployed Tethra site over HTTPS. The Firebase project
  and Hosting site are both `usetethra`.
- **Current analytics (verified 2026-08-01):** consent-first GA4 web stream
  `G-MJQHJ6JT5Z`. No Google request occurs before opt-in; advertising consent
  remains denied. See `docs/ANALYTICS.md` for the finite event inventory.
- **Current downloads (verified 2026-08-01):** the Firebase-hosted landing page
  links directly to `.dmg` and `.exe` assets on GitHub Releases because the
  Spark plan rejects installer binaries during upload. There is no ZIP wrapper.
  The macOS app is signed by Developer ID
  Application `Eesh Majithia (ZT56M637KS)`, notarized by Apple, and distributed
  with a stapled notarization ticket. Public checksums are in
  `downloads/SHA256SUMS.txt`.
- **Previous DNS / website (2026-07-24):** configured with the user's authorization on
  2026-07-24 — four apex A records to GitHub Pages (185.199.108–111.153)
  and `www` CNAME to `arnavtaduvayi.github.io`, added by the user in
  Squarespace; at that time the landing site was served from the repository's
  `gh-pages` branch and email / analytics were not configured.

---

## Original blocked-attempt record (2026-07-24, earlier the same day)

## Availability (verified read-only)

- Authoritative Verisign registry whois (`whois.verisign-grs.com`):
  `No match for domain "USETETHRA.COM"` — the exact domain was **available**
  as a standard, unregistered `.com` at the time of the check
  (registry database timestamp 2026-07-24T13:46:23Z).
- RDAP (`rdap.verisign.com/com/v1/domain/usetethra.com`): HTTP 404
  (not registered), confirming availability.
- Registrar-displayed first-year and renewal pricing could not be observed
  (see blockers), so premium status could not be conclusively ruled out at
  the registrar level; the registry shows a normal unregistered domain.

## Exact blockers (non-sensitive)

1. **No usable agent payment card.** The connected AgentCard account
   (holder: A.T., connected via Claude Code OAuth) has **zero issued
   cards**, a **cash balance of $0.00**, and **identity verification (KYC)
   in "rejected" status**. Funding the balance and completing identity
   verification both require actions only the account holder can perform.
   Per the authorization's stop conditions ("the agent card is
   unavailable"; "identity verification requires unavailable information"),
   the purchase was stopped.
2. **No browser control.** The Claude-in-Chrome extension was not connected
   in this environment, so the Squarespace Domains checkout could not be
   reached at all. For the same reason no checkout screenshot could be
   preserved; the registry evidence above is the availability record.

No alternative domain, spelling, extension, registrar, or brokerage was
attempted, and auto-renew/add-on requirements were never reached.

## What the user must do to complete the purchase

1. Resolve the AgentCard identity verification (KYC currently rejected) and
   add funds, **or** choose to purchase directly in their own Squarespace
   account with their own payment method (recommended given the KYC state).
2. If agent purchase is still desired: connect the Claude-in-Chrome
   extension, then re-authorize the purchase with the same constraints
   (exact domain `usetethra.com`, one year, non-premium price, no add-ons,
   no auto-renew, record the renewal price).
3. Availability can change at any time; re-verify before purchase.

No card details, credentials, or personal information are recorded in this
file.
