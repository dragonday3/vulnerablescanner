import Link from "next/link";
import ProjectForm from "@/components/ProjectForm";
import { listProjects } from "@/lib/api/projects";
import type { ProjectRead } from "@/lib/types/project";

// This page always reflects live backend state (projects can be created via
// the form or the API at any time), so it must never be statically
// prerendered at build time — force per-request rendering.
export const dynamic = "force-dynamic";

function formatDate(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export default async function ProjectsPage() {
  // listProjects() throws on a network error or non-2xx response (e.g. the
  // backend is unreachable). Without this try/catch that exception would
  // propagate out of the server component and hit Next's generic default
  // error boundary — a realistic failure mode (we hit a real
  // backend-unreachable bug earlier in this task) worth a friendly inline
  // message instead.
  let projects: ProjectRead[] = [];
  let loadError: string | null = null;
  try {
    projects = await listProjects();
  } catch (err) {
    loadError =
      err instanceof Error ? err.message : "Failed to load projects.";
  }

  return (
    // Explicit light background: globals.css darkens the body under
    // `prefers-color-scheme: dark`, and per the "no dark-mode toggle"
    // constraint this page always renders the same light theme rather than
    // following the system preference.
    <div className="min-h-full bg-zinc-50">
      <div className="mx-auto flex w-full max-w-3xl flex-col gap-8 px-6 py-12">
        <header className="flex flex-col gap-1">
          <h1 className="text-2xl font-semibold text-zinc-900">Projects</h1>
          <p className="text-sm text-zinc-500">
            Authorized engagements tracked in VulnSight.
          </p>
        </header>

        <section className="flex flex-col gap-3">
          <h2 className="text-sm font-medium uppercase tracking-wide text-zinc-500">
            Existing projects
          </h2>

          {loadError ? (
            <p className="rounded-lg border border-red-200 bg-red-50 px-4 py-6 text-center text-sm text-red-700">
              Couldn&apos;t load projects — is the backend running?
            </p>
          ) : projects.length === 0 ? (
            <p className="rounded-lg border border-dashed border-zinc-300 px-4 py-6 text-center text-sm text-zinc-500">
              No projects yet. Create one below to get started.
            </p>
          ) : (
            <div className="overflow-hidden rounded-lg border border-zinc-200 bg-white shadow-sm">
              <table className="w-full text-left text-sm">
                <thead className="bg-zinc-50 text-xs uppercase tracking-wide text-zinc-500">
                  <tr>
                    <th className="px-4 py-3 font-medium">Name</th>
                    <th className="px-4 py-3 font-medium">Description</th>
                    <th className="px-4 py-3 font-medium">Created</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-100">
                  {projects.map((project) => (
                    <tr key={project.id} className="hover:bg-zinc-50">
                      <td className="px-4 py-3 font-medium text-zinc-900">
                        <Link
                          href={`/projects/${project.id}`}
                          className="hover:underline"
                        >
                          {project.name}
                        </Link>
                      </td>
                      <td className="px-4 py-3 text-zinc-600">
                        {project.description || (
                          <span className="text-zinc-400">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-zinc-600">
                        {formatDate(project.created_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section>
          <ProjectForm />
        </section>
      </div>
    </div>
  );
}
