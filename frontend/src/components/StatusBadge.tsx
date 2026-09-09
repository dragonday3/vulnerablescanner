import type { ScanStatus } from "@/lib/types/scan";

/**
 * Every `ScanStatus` enum value mapped to a Tailwind color class, so no
 * status can ever fall through to an "unknown" default styling. Greys for
 * not-yet-running/terminal-without-result states, blues for the various
 * in-progress pipeline stages, green for a successful terminal state, red
 * for a failed terminal state.
 */
const STATUS_STYLES: Record<ScanStatus, string> = {
  created: "bg-zinc-100 text-zinc-700 ring-zinc-300",
  queued: "bg-zinc-200 text-zinc-700 ring-zinc-400",
  cancelled: "bg-zinc-300 text-zinc-800 ring-zinc-400",
  running: "bg-blue-100 text-blue-700 ring-blue-300",
  discovery: "bg-sky-100 text-sky-700 ring-sky-300",
  fingerprinting: "bg-cyan-100 text-cyan-700 ring-cyan-300",
  analyzing: "bg-indigo-100 text-indigo-700 ring-indigo-300",
  correlating: "bg-violet-100 text-violet-700 ring-violet-300",
  risk_analysis: "bg-purple-100 text-purple-700 ring-purple-300",
  report_generation: "bg-blue-100 text-blue-800 ring-blue-300",
  completed: "bg-green-100 text-green-700 ring-green-300",
  failed: "bg-red-100 text-red-700 ring-red-300",
};

const STATUS_LABELS: Record<ScanStatus, string> = {
  created: "Created",
  queued: "Queued",
  cancelled: "Cancelled",
  running: "Running",
  discovery: "Discovery",
  fingerprinting: "Fingerprinting",
  analyzing: "Analyzing",
  correlating: "Correlating",
  risk_analysis: "Risk Analysis",
  report_generation: "Report Generation",
  completed: "Completed",
  failed: "Failed",
};

export default function StatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset ${STATUS_STYLES[status]}`}
    >
      {STATUS_LABELS[status]}
    </span>
  );
}
