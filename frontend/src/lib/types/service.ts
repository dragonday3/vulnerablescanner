/**
 * Types mirroring the backend's Service Pydantic schema
 * (see backend Phase 3 Task 5 `ServiceRead`, and Phase 3 Tasks 1-4's
 * fingerprinting columns: `product`/`version`/`extrainfo`/
 * `fingerprint_source`/`evidence`).
 */

// The backend column is a plain nullable `String(20)`, but typing it as a
// closed union here (rather than `string | null`) means adding a new
// fingerprint source later is a type-checked reminder to update
// `FingerprintBadge`'s mapping, not a silent fallthrough.
export type FingerprintSource = "nmap-sv" | "http" | "port-guess" | null;

export interface ServiceRead {
  id: string;
  asset_id: string;
  port: number;
  protocol: string;
  state: string;
  service_name: string | null;
  product: string | null;
  version: string | null;
  extrainfo: string | null;
  fingerprint_source: FingerprintSource;
  evidence: Record<string, unknown> | null;
  created_at: string;
}
