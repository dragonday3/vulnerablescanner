import Link from "next/link";
import { notFound } from "next/navigation";
import StatusBadge from "@/components/StatusBadge";
import TargetForm from "@/components/TargetForm";
import ScanCreateButton from "@/components/ScanCreateButton";
import { getProject } from "@/lib/api/projects";
import { listTargets } from "@/lib/api/targets";
import { listScans } from "@/lib/api/scans";
import type { TargetRead } from "@/lib/types/target";
import type { ScanRead } from "@/lib/types/scan";

// This page always reflects live backend state (targets/scans can be
// created via the forms or the API at any time), so it must never be
// statically prerendered at build time — force per-request rendering,
// same reasoning as `/projects/page.tsx` (Task 11).
export const dynamic = "force-dynamic";

function shortId(id: string): string {
  return id.slice(0, 8);
}

export default async function ProjectDetailPage({
  params,
}: PageProps<"/projects/[projectId]">) {
  const { projectId } = await params;

  // getProject() is the one fetch this page cannot render without — if the
  // project doesn't exist (404) or the backend is unreachable, there is no
  // meaningful page to show, so surface Next's not-found UI rather than an
  // inline message on an otherwise-broken page.
  let project;
  try {
    project = await getProject(projectId);
  } catch {
    notFound();
  }

  // Targets and scans are independent, secondary fetches: if one fails the
  // other section (and the create forms) should still render. Same
  // try/catch-into-inline-message pattern as `/projects/page.tsx` (Task 11
  // review fix) so a fetch failure never hits Next's default error
  // boundary.
  let targets: TargetRead[] = [];
  let targetsError: string | null = null;
  try {
    targets = await listTargets(projectId);
  } catch (err) {
    targetsError =
      err instanceof Error ? err.message : "Failed to load targets.";
  }

  let scans: ScanRead[] = [];
  let scansError: string | null = null;
  try {
    scans = await listScans(projectId);
  } catch (err) {
    scansError = err instanceof Error ? err.message : "Failed to load scans.";
  }

  // ScanRead only carries `target_id`, not the target's `value` string.
  // Since targets are already fetched above for the target-list section,
  // join client-side (well, server-side here, but the same idea) against
  // that array rather than adding a backend join.
  const targetById = new Map(targets.map((target) => [target.id, target]));

  return (
    // Explicit light background, matching `/projects/page.tsx` (Task 11):
    // globals.css darkens the body under `prefers-color-scheme: dark`, and
    // per the "no dark-mode toggle" constraint this page always renders one
    // consistent light theme rather than following the system preference.
    <div className="min-h-full bg-zinc-50">
      <div className="mx-auto flex w-full max-w-3xl flex-col gap-8 px-6 py-12">
        <header className="flex flex-col gap-1">
          <Link href="/projects" className="text-sm text-zinc-500 hover:underline">
            &larr; All projects
          </Link>
          <h1 className="text-2xl font-semibold text-zinc-900">{project.name}</h1>
          {project.description && (
            <p className="text-sm text-zinc-500">{project.description}</p>
          )}
        </header>

        <section className="flex flex-col gap-3">
          <h2 className="text-sm font-medium uppercase tracking-wide text-zinc-500">
            Targets
          </h2>

          {targetsError ? (
            <p className="rounded-lg border border-red-200 bg-red-50 px-4 py-6 text-center text-sm text-red-700">
              Couldn&apos;t load targets — is the backend running?
            </p>
          ) : targets.length === 0 ? (
            <p className="rounded-lg border border-dashed border-zinc-300 px-4 py-6 text-center text-sm text-zinc-500">
              No targets yet. Add one below to get started.
            </p>
          ) : (
            <div className="overflow-hidden rounded-lg border border-zinc-200 bg-white shadow-sm">
              <table className="w-full text-left text-sm">
                <thead className="bg-zinc-50 text-xs uppercase tracking-wide text-zinc-500">
                  <tr>
                    <th className="px-4 py-3 font-medium">Value</th>
                    <th className="px-4 py-3 font-medium">Type</th>
                    <th className="px-4 py-3 font-medium">Authorization</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-100">
                  {targets.map((target) => (
                    <tr key={target.id} className="hover:bg-zinc-50">
                      <td className="px-4 py-3 font-medium text-zinc-900">
                        {target.value}
                      </td>
                      <td className="px-4 py-3 text-zinc-600">{target.target_type}</td>
                      <td className="px-4 py-3">
                        {target.authorization_confirmed ? (
                          <span className="inline-flex items-center rounded-full bg-green-100 px-2.5 py-0.5 text-xs font-medium text-green-700 ring-1 ring-inset ring-green-300">
                            Authorized
                          </span>
                        ) : (
                          <span className="inline-flex items-center rounded-full bg-red-100 px-2.5 py-0.5 text-xs font-medium text-red-700 ring-1 ring-inset ring-red-300">
                            Not authorized
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section>
          <TargetForm projectId={projectId} />
        </section>

        <section className="flex flex-col gap-3">
          <h2 className="text-sm font-medium uppercase tracking-wide text-zinc-500">
            Scans
          </h2>

          {scansError ? (
            <p className="rounded-lg border border-red-200 bg-red-50 px-4 py-6 text-center text-sm text-red-700">
              Couldn&apos;t load scans — is the backend running?
            </p>
          ) : scans.length === 0 ? (
            <p className="rounded-lg border border-dashed border-zinc-300 px-4 py-6 text-center text-sm text-zinc-500">
              No scans yet. Start one below.
            </p>
          ) : (
            <div className="overflow-hidden rounded-lg border border-zinc-200 bg-white shadow-sm">
              <table className="w-full text-left text-sm">
                <thead className="bg-zinc-50 text-xs uppercase tracking-wide text-zinc-500">
                  <tr>
                    <th className="px-4 py-3 font-medium">Scan</th>
                    <th className="px-4 py-3 font-medium">Target</th>
                    <th className="px-4 py-3 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-100">
                  {scans.map((scan) => (
                    <tr key={scan.id} className="hover:bg-zinc-50">
                      <td className="px-4 py-3 font-mono text-xs text-zinc-600">
                        {shortId(scan.id)}
                      </td>
                      <td className="px-4 py-3 text-zinc-900">
                        {targetById.get(scan.target_id)?.value ?? (
                          <span className="text-zinc-400">Unknown target</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={scan.status} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section>
          <ScanCreateButton projectId={projectId} targets={targets} />
        </section>
      </div>
    </div>
  );
}
