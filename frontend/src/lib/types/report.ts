/**
 * Types mirroring the backend's Report Pydantic schema and its `summary`
 * JSONB document (see backend Phase 8 `ReportRead` /
 * `report_builder.build_report_summary`).
 *
 * `ReportRead.summary` is a passthrough `dict` on the backend, not
 * independently validated by Pydantic — same convention as `evidence`'s
 * `Record<string, unknown>` typing elsewhere. `ReportSummary` here is a
 * hand-maintained mirror of `report_builder.py`'s actual output shape;
 * there is no schema to regenerate from, so a future backend-side shape
 * change must be mirrored here by hand.
 */
import type { Severity, ValidationState } from "./finding";

export interface ReportSummary {
  target: { value: string; target_type: string };
  risk: { score: number | null; tier: Severity | null };
  findings_summary: {
    total: number;
    by_severity: Record<Severity, number>;
    by_validation_state: Record<ValidationState, number>;
  };
  misconfigurations_summary: {
    total: number;
    by_severity: Record<Severity, number>;
  };
  assets: Array<{
    host: string;
    risk_score: number | null;
    risk_tier: Severity | null;
    services: Array<{
      port: number;
      protocol: string;
      service_name: string | null;
      product: string | null;
      version: string | null;
      findings: Array<{
        cve_id: string;
        severity: Severity;
        cvss_score: number | null;
        confidence_score: number;
        validation_state: ValidationState;
      }>;
      misconfigurations: Array<{
        check_id: string;
        title: string;
        severity: Severity;
        description: string;
      }>;
    }>;
  }>;
}

export interface ReportRead {
  id: string;
  scan_id: string;
  summary: ReportSummary;
  generated_at: string;
}
