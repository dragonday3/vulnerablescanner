/**
 * Types mirroring the backend's Misconfiguration Pydantic schema
 * (see backend Phase 6 Task 5 `MisconfigurationRead`, nested on
 * `ServiceRead.misconfigurations` via `GET /scans/{scan_id}/assets`).
 */

// Reuse the existing `Severity` type from finding.ts rather than inventing
// a parallel one — `SeverityBadge` already renders any `Severity` value.
import type { Severity } from "./finding";

export interface MisconfigurationRead {
  id: string;
  service_id: string;
  check_id: string;
  title: string;
  severity: Severity;
  description: string;
  evidence: Record<string, unknown>;
  created_at: string;
}
