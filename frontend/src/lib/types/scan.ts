/**
 * Types mirroring the backend's Scan Pydantic schemas
 * (see backend Task 5 `ScanStatus` enum and Task 6-8 `ScanRead` / `ScanCreate`).
 */

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
}

export interface ScanCreate {
  project_id: string;
  target_id: string;
  config?: Record<string, unknown>;
}
