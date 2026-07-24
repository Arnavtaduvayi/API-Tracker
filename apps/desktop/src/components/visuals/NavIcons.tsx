// Minimal stroke icons for the sidebar. They exist so the collapsed rail is
// still readable — a column of identical dots would not be. Each icon is
// paired with the destination's exact label as a tooltip in App.tsx.

const PATHS: Record<string, JSX.Element> = {
  // Vault
  projects: (
    <path d="M2 4.5A1.5 1.5 0 0 1 3.5 3h3l1.2 1.6h4.8A1.5 1.5 0 0 1 14 6.1v6.4A1.5 1.5 0 0 1 12.5 14h-9A1.5 1.5 0 0 1 2 12.5Z" />
  ),
  providers: (
    <>
      <rect x="2.2" y="2.2" width="5" height="5" rx="1" />
      <rect x="8.8" y="2.2" width="5" height="5" rx="1" />
      <rect x="2.2" y="8.8" width="5" height="5" rx="1" />
      <rect x="8.8" y="8.8" width="5" height="5" rx="1" />
    </>
  ),
  // Exposure
  scan: (
    <>
      <circle cx="7.2" cy="7.2" r="4.2" />
      <path d="m10.4 10.4 3 3" />
    </>
  ),
  env: (
    <>
      <path d="M3.5 2.2h6l3.2 3.2v8.4a.6.6 0 0 1-.6.6H3.5a.6.6 0 0 1-.6-.6V2.8a.6.6 0 0 1 .6-.6Z" />
      <path d="M9.3 2.4v3.2h3.2" />
    </>
  ),
  // Delivery
  destinations: (
    <>
      <rect x="2.2" y="2.6" width="11.6" height="4.2" rx="1" />
      <rect x="2.2" y="9.2" width="11.6" height="4.2" rx="1" />
      <path d="M4.8 4.7h.01M4.8 11.3h.01" />
    </>
  ),
  sync: (
    <>
      <path d="M13.2 7.2a5.2 5.2 0 0 0-9.1-3.1M2.8 8.8a5.2 5.2 0 0 0 9.1 3.1" />
      <path d="M3.9 1.7v2.6h2.6M12.1 14.3v-2.6H9.5" />
    </>
  ),
  rotation: (
    <>
      <path d="M13.4 8a5.4 5.4 0 1 1-1.9-4.1" />
      <path d="M13.6 2.2v3.4h-3.4" />
    </>
  ),
  access: (
    <>
      <circle cx="8" cy="8" r="5.6" />
      <path d="M8 4.6V8l2.3 1.4" />
    </>
  ),
  // Monitoring
  alerts: (
    <>
      <path d="M4.2 6.6a3.8 3.8 0 0 1 7.6 0c0 3 1.1 4 1.1 4H3.1s1.1-1 1.1-4Z" />
      <path d="M6.7 13a1.5 1.5 0 0 0 2.6 0" />
    </>
  ),
  notify: (
    <>
      <path d="M2.4 8.4 13.4 3.1l-2.6 10.6-2.9-4.1Z" />
      <path d="m7.9 9.6 5.5-6.5" />
    </>
  ),
  usage: (
    <>
      <path d="M2.6 13.4h10.8" />
      <path d="M4.6 13.4V8.2M8 13.4V3.6M11.4 13.4v-3.6" />
    </>
  ),
  pricing: (
    <>
      <path d="M8 2.4v11.2" />
      <path d="M10.7 4.8H6.7a1.9 1.9 0 0 0 0 3.8h2.6a1.9 1.9 0 0 1 0 3.8H5.1" />
    </>
  ),
  // System
  templates: (
    <>
      <path d="m8 2.2 5.6 3-5.6 3-5.6-3Z" />
      <path d="m2.4 8 5.6 3 5.6-3M2.4 11.1l5.6 3 5.6-3" />
    </>
  ),
  backup: (
    <>
      <rect x="2.2" y="3" width="11.6" height="3.2" rx="0.8" />
      <path d="M3.4 6.2v6.2a.6.6 0 0 0 .6.6h8a.6.6 0 0 0 .6-.6V6.2" />
      <path d="M6.6 9h2.8" />
    </>
  ),
  settings: (
    <>
      <circle cx="8" cy="8" r="2.1" />
      <path d="M12.6 9.8a1.2 1.2 0 0 0 .24 1.32l.05.05a1.4 1.4 0 1 1-2 2l-.04-.05a1.2 1.2 0 0 0-2.05.86v.12a1.4 1.4 0 1 1-2.8 0v-.06a1.2 1.2 0 0 0-2.1-.82l-.05.05a1.4 1.4 0 1 1-2-2l.05-.04a1.2 1.2 0 0 0-.86-2.05H1a1.4 1.4 0 1 1 0-2.8h.06a1.2 1.2 0 0 0 .82-2.1l-.05-.05a1.4 1.4 0 1 1 2-2l.04.05a1.2 1.2 0 0 0 2.05-.86V1a1.4 1.4 0 1 1 2.8 0v.06a1.2 1.2 0 0 0 2.05.86l.05-.05a1.4 1.4 0 1 1 2 2l-.05.04a1.2 1.2 0 0 0 .86 2.05H15a1.4 1.4 0 1 1 0 2.8h-.06a1.2 1.2 0 0 0-1.1.73Z" />
    </>
  ),
};

export function NavIcon({ name }: { name: string }) {
  return (
    <svg
      className="nav-icon"
      viewBox="0 0 16 16"
      width="16"
      height="16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.3"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {PATHS[name] ?? <circle cx="8" cy="8" r="3" />}
    </svg>
  );
}
