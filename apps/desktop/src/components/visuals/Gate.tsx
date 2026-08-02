// Vault gate shell (create / unlock). The ambient particle field is masked
// away from the form so the left side remains calm and readable.

import type { ReactNode } from "react";
import { BrandLockup } from "./BrandLockup";
import { ParticleField } from "./ParticleField";

export function Gate({ eyebrow, children }: { eyebrow: string; children: ReactNode }) {
  return (
    <div className="gate">
      <ParticleField density={1.15} mode="vault" />
      <div className="gate-form">
        <BrandLockup className="gate-brand" />
        <p className="gate-eyebrow">{eyebrow}</p>
        {children}
      </div>
    </div>
  );
}
