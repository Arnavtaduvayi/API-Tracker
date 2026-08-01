// Two-column shell for the vault gate screens (create / unlock).
//
// It wraps the existing VaultSetup and VaultUnlock components without
// modifying them: they render into the left column exactly as before, while
// the right column carries the decorative wireframe globe.

import type { ReactNode } from "react";
import { BrandLockup } from "./BrandLockup";
import { ParticleField } from "./ParticleField";
import { WireGlobe } from "./WireGlobe";

export function Gate({ eyebrow, children }: { eyebrow: string; children: ReactNode }) {
  return (
    <div className="gate">
      <ParticleField density={1.15} mode="vault" />
      <div className="gate-form">
        <BrandLockup className="gate-brand" />
        <p className="gate-eyebrow">{eyebrow}</p>
        {children}
      </div>
      <div className="gate-art">
        <WireGlobe className="globe-wrap" />
      </div>
    </div>
  );
}
