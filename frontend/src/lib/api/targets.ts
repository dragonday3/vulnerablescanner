import { request } from "./client";
import type { TargetCreate, TargetRead } from "@/lib/types/target";

/** GET /projects/{id}/targets — used by the /projects/[projectId] page (Task 12). */
export function listTargets(projectId: string): Promise<TargetRead[]> {
  return request<TargetRead[]>(`/projects/${projectId}/targets`);
}

/** POST /projects/{id}/targets — used by TargetForm (Task 12). */
export function createTarget(
  projectId: string,
  payload: TargetCreate,
): Promise<TargetRead> {
  return request<TargetRead>(`/projects/${projectId}/targets`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}
