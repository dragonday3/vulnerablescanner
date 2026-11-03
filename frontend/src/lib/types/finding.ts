/**
 * Types mirroring the backend's Finding Pydantic schema
 * (see backend Phase 4 Task 6 `FindingRead`, nested on `ServiceRead.findings`
 * via `GET /scans/{scan_id}/assets`).
 */

// CVSS itself defines a None/Low/Medium/High/Critical severity banding, so
// "NONE" is a real, non-null value here (a CVE with no CVSS metrics at all
// legitimately IS severity "NONE") — unlike `FingerprintSource`, this union
// has no `null` member.
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";

// Phase 5: a human operator's judgment call on a Finding, independent of
// confidence_score. "unvalidated" is the default/overwhelmingly common
// value — see ValidationBadge, which deliberately renders nothing for it.
export type ValidationState = "unvalidated" | "confirmed" | "false_positive";

export interface FindingRead {
  id: string;
  service_id: string;
  cve_id: string;
  matched_cpe: string;
  severity: Severity;
  cvss_score: number | null;
  cvss_vector: string | null;
  description: string | null;
  evidence: Record<string, unknown>;
  created_at: string;
  // --- Phase 5 additions ---
  confidence_score: number;
  validation_state: ValidationState;
  validation_note: string | null;
  validated_at: string | null;
}

// Body for PATCH /findings/{id}. validation_note is always optional and is
// a full replace, never merged with whatever note was there before (see
// backend's finding_service.py).
export interface FindingValidationUpdate {
  validation_state: ValidationState;
  validation_note?: string | null;
}
