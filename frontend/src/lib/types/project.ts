/**
 * Types mirroring the backend's Project Pydantic schemas
 * (see backend Task 6-7 `ProjectRead` / `ProjectCreate`).
 */

export interface ProjectRead {
  id: string;
  name: string;
  description: string | null;
  created_at: string;
  updated_at: string;
}

export interface ProjectCreate {
  name: string;
  description?: string | null;
}
