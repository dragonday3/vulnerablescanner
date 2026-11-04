/**
 * Types mirroring the backend's Asset Pydantic schema
 * (see backend Phase 3 Task 5 `AssetRead`).
 */

import type { ServiceRead } from "./service";
// Reuse the existing `Severity` type from finding.ts rather than inventing a
// parallel one — same precedent as `misconfiguration.ts`.
import type { Severity } from "./finding";

export interface AssetRead {
  id: string;
  project_id: string;
  target_id: string;
  scan_id: string;
  host: string;
  created_at: string;
  services: ServiceRead[];
  // Phase 7: null until this asset's own risk scoring has run; a scored
  // asset with zero findings/misconfigs lands on 0.0/"NONE", never null.
  risk_score: number | null;
  risk_tier: Severity | null;
}
