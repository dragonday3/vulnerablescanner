import { request } from "./client";
import type { ProjectCreate, ProjectRead } from "@/lib/types/project";

/** GET /projects — used by the /projects list page (Task 11). */
export function listProjects(): Promise<ProjectRead[]> {
  return request<ProjectRead[]>("/projects");
}

/** POST /projects — used by ProjectForm (Task 11). */
export function createProject(payload: ProjectCreate): Promise<ProjectRead> {
  return request<ProjectRead>("/projects", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

/** GET /projects/{id} — used by the /projects/[projectId] page (Task 12). */
export function getProject(id: string): Promise<ProjectRead> {
  return request<ProjectRead>(`/projects/${id}`);
}
