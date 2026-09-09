import { request } from "./client";
import type { ScanCreate, ScanRead } from "@/lib/types/scan";

/**
 * GET /scans (optionally filtered by project_id) — used by the
 * /projects/[projectId] page (Task 12) to list a project's scans.
 */
export function listScans(projectId?: string): Promise<ScanRead[]> {
  const query = projectId ? `?project_id=${encodeURIComponent(projectId)}` : "";
  return request<ScanRead[]>(`/scans${query}`);
}

/** POST /scans — used by ScanCreateButton (Task 12). */
export function createScan(payload: ScanCreate): Promise<ScanRead> {
  return request<ScanRead>("/scans", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}
