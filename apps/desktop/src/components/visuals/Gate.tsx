// Two-column shell for the vault gate screens (create / unlock).
//
// It wraps the existing VaultSetup and VaultUnlock components without
// modifying them: they render into the left column exactly as before, while
// the right column carries the decorative wireframe globe.

import type { ReactNode } from "react";
import { WireGlobe } from "./WireGlobe";

export function Gate({ eyebrow, children }: { eyebrow: string; children: ReactNode }) {
  return (
    <div className="gate">
      <div className="gate-form">
        <p className="gate-eyebrow">{eyebrow}</p>
        {children}
      </div>
      <div className="gate-art">
        <WireGlobe className="globe-wrap" />
      </div>
    </div>
  );
}
