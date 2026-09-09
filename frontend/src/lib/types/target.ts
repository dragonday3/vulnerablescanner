/**
 * Types mirroring the backend's Target Pydantic schemas
 * (see backend Task 6-7 `TargetRead` / `TargetCreate`).
 */

export type TargetType = "ip" | "domain" | "hostname" | "cidr";

export interface TargetRead {
  id: string;
  project_id: string;
  value: string;
  target_type: TargetType;
  authorization_confirmed: boolean;
  authorization_note: string | null;
  created_at: string;
}

export interface TargetCreate {
  value: string;
  target_type: TargetType;
  authorization_confirmed: boolean;
  authorization_note?: string | null;
}
