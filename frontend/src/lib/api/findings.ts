import { request } from "./client";
import type { FindingRead, FindingValidationUpdate } from "@/lib/types/finding";

/** PATCH /findings/{id} — used by FindingValidationControl (Phase 5 Task 4). */
export function updateFindingValidation(
  findingId: string,
  payload: FindingValidationUpdate,
): Promise<FindingRead> {
  return request<FindingRead>(`/findings/${findingId}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}
