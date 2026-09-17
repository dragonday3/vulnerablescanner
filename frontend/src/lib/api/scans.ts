import { request } from "./client";
import type { ScanCreate, ScanRead } from "@/lib/types/scan";
import type { AssetRead } from "@/lib/types/asset";

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

/** GET /scans/{id} — used by the /projects/[projectId]/scans/[scanId] page (Phase 3 Task 6). */
export function getScan(scanId: string): Promise<ScanRead> {
  return request<ScanRead>(`/scans/${scanId}`);
}

/** GET /scans/{id}/assets — used by the /projects/[projectId]/scans/[scanId] page (Phase 3 Task 6). */
export function getScanAssets(scanId: string): Promise<AssetRead[]> {
  return request<AssetRead[]>(`/scans/${scanId}/assets`);
}
