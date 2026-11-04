import Link from "next/link";
import { notFound } from "next/navigation";
import SeverityBadge from "@/components/SeverityBadge";
import ValidationBadge from "@/components/ValidationBadge";
import PrintButton from "@/components/PrintButton";
import { getScanReport } from "@/lib/api/scans";
import type { ReportRead } from "@/lib/types/report";

// The underlying Report row never changes once generated, but this page is
// reached via a live navigation flow (same scan-results page a scan is
// still being polled on) — force-dynamic for the same reason as the
// results page itself, rather than assuming a static prerender is safe.
export const dynamic = "force-dynamic";

function shortId(id: string): string {
  return id.slice(0, 8);
}

// Combine product + version into one display string, same convention as
// the scan-results page's own productVersion helper.
function productVersion(service: {
  product: string | null;
  version: string | null;
}): string {
  if (service.product && service.version) return `${service.product} ${service.version}`;
  if (service.product) return service.product;
  return "-";
}

export default async function ScanReportPage({
  params,
}: PageProps<"/projects/[projectId]/scans/[scanId]/report">) {
  const { projectId, scanId } = await params;

  // getScanReport() is the one fetch this page cannot render without — a
  // genuine 404 (no Report yet, or the scan itself doesn't exist) routes to
  // Next's not-found UI, distinct from a backend-unreachable/network
  // failure, which falls through to the same inline "couldn't load" error
  // card the scan-results page uses for its own getScan() call.
  let report: ReportRead;
  try {
    report = await getScanReport(scanId);
  } catch (err) {
    const message = err instanceof Error ? err.message : "";
    if (message.startsWith("API error 404:")) {
      notFound();
    }
    return (
      <div className="min-h-screen bg-zinc-50">
        <div className="mx-auto flex w-full max-w-3xl flex-col gap-6 px-6 py-12">
          <Link
            href={`/projects/${projectId}/scans/${scanId}`}
            className="text-sm text-zinc-500 hover:underline print:hidden"
          >
            &larr; Back to scan
          </Link>
          <p className="rounded-lg border border-red-200 bg-red-50 px-4 py-6 text-center text-sm text-red-700">
            Couldn&apos;t load this report — is the backend running?
          </p>
        </div>
      </div>
    );
  }

  const { summary } = report;

  return (
    <div className="min-h-screen bg-zinc-50">
      <div className="mx-auto flex w-full max-w-3xl flex-col gap-8 px-6 py-12">
        <header className="flex flex-col gap-3">
          <div className="flex items-center justify-between print:hidden">
            <Link
              href={`/projects/${projectId}/scans/${scanId}`}
              className="text-sm text-zinc-500 hover:underline"
            >
              &larr; Back to scan
            </Link>
            <PrintButton />
          </div>
          <h1 className="text-2xl font-semibold text-zinc-900">
            Report — Scan {shortId(report.scan_id)}
          </h1>
          <p className="text-sm text-zinc-500">
            Target: <span className="font-mono text-zinc-700">{summary.target.value}</span>{" "}
            <span className="text-zinc-400">({summary.target.target_type})</span>
          </p>
          <p className="text-xs text-zinc-400">Generated {report.generated_at}</p>
        </header>

        <section className="flex flex-col gap-3 rounded-lg border border-zinc-200 bg-white p-5 shadow-sm">
          <h2 className="text-sm font-medium uppercase tracking-wide text-zinc-500">
            Overall Risk
          </h2>
          {summary.risk.tier != null ? (
            <div className="flex items-center gap-2">
              <SeverityBadge severity={summary.risk.tier} />
              <span className="text-sm text-zinc-700">
                Score: {summary.risk.score?.toFixed(1)}
              </span>
            </div>
          ) : (
            <p className="text-sm text-zinc-400">Not scored.</p>
          )}
        </section>

        <section className="flex flex-col gap-3 rounded-lg border border-zinc-200 bg-white p-5 shadow-sm">
          <h2 className="text-sm font-medium uppercase tracking-wide text-zinc-500">
            Findings — {summary.findings_summary.total} total
          </h2>
          <div className="flex flex-wrap gap-4 text-sm">
            <div className="flex flex-col gap-1">
              <span className="text-xs uppercase tracking-wide text-zinc-500">By severity</span>
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(summary.findings_summary.by_severity).map(([severity, count]) => (
                  <span key={severity} className="flex items-center gap-1">
                    <SeverityBadge severity={severity as keyof typeof summary.findings_summary.by_severity} />
                    <span className="text-zinc-600">{count}</span>
                  </span>
                ))}
              </div>
            </div>
            <div className="flex flex-col gap-1">
              <span className="text-xs uppercase tracking-wide text-zinc-500">
                By validation state
              </span>
              <div className="flex flex-wrap gap-3 text-zinc-600">
                <span>Unvalidated: {summary.findings_summary.by_validation_state.unvalidated}</span>
                <span>Confirmed: {summary.findings_summary.by_validation_state.confirmed}</span>
                <span>
                  False positive: {summary.findings_summary.by_validation_state.false_positive}
                </span>
              </div>
            </div>
          </div>
        </section>

        <section className="flex flex-col gap-3 rounded-lg border border-zinc-200 bg-white p-5 shadow-sm">
          <h2 className="text-sm font-medium uppercase tracking-wide text-zinc-500">
            Misconfigurations — {summary.misconfigurations_summary.total} total
          </h2>
          <div className="flex flex-col gap-1">
            <span className="text-xs uppercase tracking-wide text-zinc-500">By severity</span>
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(summary.misconfigurations_summary.by_severity).map(
                ([severity, count]) => (
                  <span key={severity} className="flex items-center gap-1">
                    <SeverityBadge
                      severity={severity as keyof typeof summary.misconfigurations_summary.by_severity}
                    />
                    <span className="text-sm text-zinc-600">{count}</span>
                  </span>
                ),
              )}
            </div>
          </div>
        </section>

        <section className="flex flex-col gap-3">
          <h2 className="text-sm font-medium uppercase tracking-wide text-zinc-500">
            Assets
          </h2>

          {summary.assets.length === 0 ? (
            <p className="rounded-lg border border-dashed border-zinc-300 px-4 py-6 text-center text-sm text-zinc-500">
              No assets in this report.
            </p>
          ) : (
            summary.assets.map((asset) => (
              <div
                key={asset.host}
                className="overflow-hidden rounded-lg border border-zinc-200 bg-white shadow-sm"
              >
                <div className="flex flex-wrap items-center gap-1.5 border-b border-zinc-100 px-4 py-3">
                  <span className="font-mono text-xs text-zinc-600">{asset.host}</span>
                  {asset.risk_tier != null && (
                    <>
                      <SeverityBadge severity={asset.risk_tier} />
                      <span className="text-xs text-zinc-500">
                        Risk: {asset.risk_score?.toFixed(1)}
                      </span>
                    </>
                  )}
                </div>

                {asset.services.length === 0 ? (
                  <p className="px-4 py-6 text-center text-sm text-zinc-400">
                    No services discovered.
                  </p>
                ) : (
                  <table className="w-full text-left text-sm">
                    <thead className="bg-zinc-50 text-xs uppercase tracking-wide text-zinc-500">
                      <tr>
                        <th className="px-4 py-3 font-medium">Port</th>
                        <th className="px-4 py-3 font-medium">Protocol</th>
                        <th className="px-4 py-3 font-medium">Service</th>
                        <th className="px-4 py-3 font-medium">Product / Version</th>
                        <th className="px-4 py-3 font-medium">Findings &amp; Misconfigurations</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-100">
                      {asset.services.map((service) => (
                        <tr key={`${asset.host}-${service.port}-${service.protocol}`}>
                          <td className="px-4 py-3 text-zinc-900">{service.port}</td>
                          <td className="px-4 py-3 text-zinc-600">{service.protocol}</td>
                          <td className="px-4 py-3 text-zinc-600">
                            {service.service_name ?? "-"}
                          </td>
                          <td className="px-4 py-3 text-zinc-600">{productVersion(service)}</td>
                          <td className="px-4 py-3">
                            {service.findings.length === 0 &&
                            service.misconfigurations.length === 0 ? (
                              <span className="text-xs text-zinc-400">None</span>
                            ) : (
                              <div className="flex flex-col gap-1">
                                {service.findings.map((finding, index) => (
                                  <div
                                    key={`${finding.cve_id}-${index}`}
                                    className={`flex flex-wrap items-center gap-1.5 ${
                                      finding.validation_state === "false_positive"
                                        ? "opacity-50"
                                        : ""
                                    }`}
                                  >
                                    <SeverityBadge severity={finding.severity} />
                                    <a
                                      href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className={`font-mono text-xs text-blue-600 hover:underline ${
                                        finding.validation_state === "false_positive"
                                          ? "line-through"
                                          : ""
                                      }`}
                                    >
                                      {finding.cve_id}
                                    </a>
                                    {finding.cvss_score != null && (
                                      <span className="text-xs text-zinc-500">
                                        (CVSS {finding.cvss_score})
                                      </span>
                                    )}
                                    <span className="text-xs text-zinc-500">
                                      Confidence: {Math.round(finding.confidence_score)}/100
                                    </span>
                                    <ValidationBadge state={finding.validation_state} />
                                  </div>
                                ))}
                                {service.misconfigurations.map((misconfig) => (
                                  <div
                                    key={misconfig.check_id}
                                    className="flex flex-wrap items-center gap-1.5"
                                  >
                                    <SeverityBadge severity={misconfig.severity} />
                                    <span className="text-xs text-zinc-700">
                                      {misconfig.title}
                                    </span>
                                    <span className="text-xs text-zinc-500">
                                      {misconfig.description}
                                    </span>
                                  </div>
                                ))}
                              </div>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            ))
          )}
        </section>
      </div>
    </div>
  );
}
