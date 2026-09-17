/**
 * Types mirroring the backend's Asset Pydantic schema
 * (see backend Phase 3 Task 5 `AssetRead`).
 */

import type { ServiceRead } from "./service";

export interface AssetRead {
  id: string;
  project_id: string;
  target_id: string;
  scan_id: string;
  host: string;
  created_at: string;
  services: ServiceRead[];
}
