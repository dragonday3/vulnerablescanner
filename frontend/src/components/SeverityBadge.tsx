import type { Severity } from "@/lib/types/finding";

/**
 * Every `Severity` value mapped to a Tailwind color class, same "exhaustive
 * Record" convention as `StatusBadge.tsx`/`FingerprintBadge.tsx`. Unlike
 * `FingerprintSource`, `Severity` has no `null` member — "NONE" is a real,
 * non-null CVSS banding (see `finding.ts`) — so this is a plain
 * `Record<Severity, string>`, no separate null-case branch needed.
 */
const SEVERITY_STYLES: Record<Severity, string> = {
  CRITICAL: "bg-red-100 text-red-800 ring-red-400",
  HIGH: "bg-orange-100 text-orange-700 ring-orange-300",
  MEDIUM: "bg-amber-100 text-amber-700 ring-amber-300",
  LOW: "bg-sky-100 text-sky-700 ring-sky-300",
  NONE: "bg-zinc-100 text-zinc-500 ring-zinc-300",
};

export default function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset ${SEVERITY_STYLES[severity]}`}
    >
      {severity}
    </span>
  );
}
