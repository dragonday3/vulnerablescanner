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
}
