import Link from "next/link";
import { notFound } from "next/navigation";
import StatusBadge from "@/components/StatusBadge";
import FingerprintBadge from "@/components/FingerprintBadge";
import { getScan, getScanAssets } from "@/lib/api/scans";
import { listTargets } from "@/lib/api/targets";
import type { ScanRead } from "@/lib/types/scan";
import type { TargetRead } from "@/lib/types/target";
import type { AssetRead } from "@/lib/types/asset";
import type { ServiceRead } from "@/lib/types/service";

// Scan/asset/service state changes live as a scan progresses through the
// pipeline, so this page must never be statically prerendered — same
// reasoning as `/projects/[projectId]/page.tsx`.
export const dynamic = "force-dynamic";

function shortId(id: string): string {
  return id.slice(0, 8);
}

// Combine product + version into one display string: "nginx 1.24.0" when
// both are present, just the product when only that's known, "-" when
// neither was captured (e.g. no fingerprinting was possible for this port).
function productVersion(service: ServiceRead): string {
  if (service.product && service.version) return `${service.product} ${service.version}`;
  if (service.product) return service.product;
  return "-";
}

export default async function ScanResultsPage({
  params,
}: PageProps<"/projects/[projectId]/scans/[scanId]">) {
  const { projectId, scanId } = await params;

  // getScan() is the one fetch this page cannot render without — a genuine
  // 404 (scan doesn't exist) routes to Next's not-found UI, distinct from a
  // backend-unreachable/network failure, which falls through to the same
  // inline "couldn't load" error card `/projects/[projectId]/page.tsx` uses.
  let scan: ScanRead;
  try {
    scan = await getScan(scanId);
  } catch (err) {
    const message = err instanceof Error ? err.message : "";
    if (message.startsWith("API error 404:")) {
      notFound();
    }
    return (
      <div className="min-h-screen bg-zinc-50">
        <div className="mx-auto flex w-full max-w-3xl flex-col gap-6 px-6 py-12">
          <Link
            href={`/projects/${projectId}`}
            className="text-sm text-zinc-500 hover:underline"
          >
            &larr; Back to project
          </Link>
          <p className="rounded-lg border border-red-200 bg-red-50 px-4 py-6 text-center text-sm text-red-700">
            Couldn&apos;t load this scan — is the backend running?
          </p>
        </div>
      </div>
    );
  }

  // Targets and assets are independent, secondary fetches: if one fails the
  // rest of the page should still render. Same try/catch-into-inline-
  // message pattern as `/projects/[projectId]/page.tsx`.
  let targets: TargetRead[] = [];
  let targetsError: string | null = null;
  try {
    targets = await listTargets(projectId);
  } catch (err) {
    targetsError = err instanceof Error ? err.message : "Failed to load target.";
  }

  let assets: AssetRead[] = [];
  let assetsError: string | null = null;
  try {
    assets = await getScanAssets(scanId);
  } catch (err) {
    assetsError = err instanceof Error ? err.message : "Failed to load results.";
  }

  // ScanRead only carries `target_id`, not the target's `value`/`target_type`
  // — join client-side against the full target list, same approach the
  // project page already uses for its scan table.
  const targetById = new Map(targets.map((target) => [target.id, target]));
  const target = targetById.get(scan.target_id);

  return (
    <div className="min-h-screen bg-zinc-50">
      <div className="mx-auto flex w-full max-w-3xl flex-col gap-8 px-6 py-12">
        <header className="flex flex-col gap-1">
          <Link
            href={`/projects/${projectId}`}
            className="text-sm text-zinc-500 hover:underline"
          >
            &larr; Back to project
          </Link>
          <h1 className="text-2xl font-semibold text-zinc-900">
            Scan {shortId(scan.id)}
          </h1>
        </header>

        <section className="flex flex-col gap-3 rounded-lg border border-zinc-200 bg-white p-5 shadow-sm">
          <div className="flex flex-wrap items-center gap-3">
            <StatusBadge status={scan.status} />
            {targetsError ? (
              <span className="text-sm text-red-600">Couldn&apos;t load target.</span>
            ) : target ? (
              <span className="text-sm text-zinc-900">
                {target.value}{" "}
                <span className="text-zinc-500">({target.target_type})</span>
              </span>
            ) : (
              <span className="text-sm text-zinc-400">Unknown target</span>
            )}
          </div>

          <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-sm sm:grid-cols-3">
            <div>
              <dt className="text-xs uppercase tracking-wide text-zinc-500">Created</dt>
              <dd className="text-zinc-700">{scan.created_at}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-zinc-500">Started</dt>
              <dd className="text-zinc-700">{scan.started_at ?? "-"}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-zinc-500">Completed</dt>
              <dd className="text-zinc-700">{scan.completed_at ?? "-"}</dd>
            </div>
          </dl>

          {scan.status === "failed" && scan.error_message && (
            <p className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
              {scan.error_message}
            </p>
          )}
        </section>

        <section className="flex flex-col gap-3">
          <h2 className="text-sm font-medium uppercase tracking-wide text-zinc-500">
            Results
          </h2>

          {assetsError ? (
            <p className="rounded-lg border border-red-200 bg-red-50 px-4 py-6 text-center text-sm text-red-700">
              Couldn&apos;t load results — is the backend running?
            </p>
          ) : assets.length === 0 ? (
            <p className="rounded-lg border border-dashed border-zinc-300 px-4 py-6 text-center text-sm text-zinc-500">
              No results yet — scan is {scan.status}.
            </p>
          ) : (
            assets.map((asset) => (
              <div
                key={asset.id}
                className="overflow-hidden rounded-lg border border-zinc-200 bg-white shadow-sm"
              >
                <div className="border-b border-zinc-100 px-4 py-3">
                  <span className="font-mono text-xs text-zinc-600">{asset.host}</span>
                </div>
                <table className="w-full text-left text-sm">
                  <thead className="bg-zinc-50 text-xs uppercase tracking-wide text-zinc-500">
                    <tr>
                      <th className="px-4 py-3 font-medium">Port</th>
                      <th className="px-4 py-3 font-medium">Protocol</th>
                      <th className="px-4 py-3 font-medium">State</th>
                      <th className="px-4 py-3 font-medium">Service</th>
                      <th className="px-4 py-3 font-medium">Product / Version</th>
                      <th className="px-4 py-3 font-medium">Fingerprint</th>
                      <th className="px-4 py-3 font-medium">Evidence</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-100">
                    {asset.services.map((service) => (
                      <tr key={service.id} className="hover:bg-zinc-50">
                        <td className="px-4 py-3 text-zinc-900">{service.port}</td>
                        <td className="px-4 py-3 text-zinc-600">{service.protocol}</td>
                        <td className="px-4 py-3 text-zinc-600">{service.state}</td>
                        <td className="px-4 py-3 text-zinc-600">
                          {service.service_name ?? "-"}
                        </td>
                        <td className="px-4 py-3 text-zinc-600">
                          {productVersion(service)}
                        </td>
                        <td className="px-4 py-3">
                          <FingerprintBadge source={service.fingerprint_source} />
                        </td>
                        <td className="px-4 py-3">
                          <details>
                            <summary className="cursor-pointer text-xs text-zinc-500 hover:underline">
                              Raw
                            </summary>
                            <pre className="mt-2 max-w-sm overflow-x-auto rounded bg-zinc-50 p-2 text-xs text-zinc-700">
                              {JSON.stringify(service.evidence, null, 2)}
                            </pre>
                          </details>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))
          )}
        </section>
      </div>
    </div>
  );
}
