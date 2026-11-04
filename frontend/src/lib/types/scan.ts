/**
 * Types mirroring the backend's Scan Pydantic schemas
 * (see backend Task 5 `ScanStatus` enum and Task 6-8 `ScanRead` / `ScanCreate`).
 */

// Reuse the existing `Severity` type from finding.ts rather than inventing a
// parallel one — same precedent as `misconfiguration.ts` — so `SeverityBadge`
// needs zero changes to render a risk tier.
import type { Severity } from "./finding";

export type ScanStatus =
  | "created"
  | "queued"
  | "running"
  | "discovery"
  | "fingerprinting"
  | "analyzing"
  | "correlating"
  | "risk_analysis"
  | "report_generation"
  | "completed"
  | "failed"
  | "cancelled";

export interface ScanRead {
  id: string;
  project_id: string;
  target_id: string;
  status: ScanStatus;
  config: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  // Phase 7: null until the scan reaches RISK_ANALYSIS; a scored scan with
  // zero findings/misconfigs lands on 0.0/"NONE", never null again.
  risk_score: number | null;
  risk_tier: Severity | null;
}

export interface ScanCreate {
  project_id: string;
  target_id: string;
  config?: Record<string, unknown>;
}
