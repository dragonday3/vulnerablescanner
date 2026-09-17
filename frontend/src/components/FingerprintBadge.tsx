import type { FingerprintSource } from "@/lib/types/service";

/**
 * Every non-null `FingerprintSource` value mapped to a Tailwind color
 * class, same "exhaustive Record" convention as `StatusBadge.tsx` — adding
 * a new fingerprint source later is a type error here, not a silent
 * fallthrough. `null` (never fingerprinted) is handled separately below
 * with a distinct neutral/muted style, since it isn't a member of this
 * Record's key type.
 */
const SOURCE_STYLES: Record<Exclude<FingerprintSource, null>, string> = {
  "nmap-sv": "bg-cyan-100 text-cyan-700 ring-cyan-300",
  http: "bg-indigo-100 text-indigo-700 ring-indigo-300",
  "port-guess": "bg-amber-100 text-amber-700 ring-amber-300",
};

const SOURCE_LABELS: Record<Exclude<FingerprintSource, null>, string> = {
  "nmap-sv": "nmap -sV",
  http: "HTTP probe",
  "port-guess": "Port guess",
};

const UNFINGERPRINTED_STYLE = "bg-zinc-100 text-zinc-500 ring-zinc-300";

export default function FingerprintBadge({ source }: { source: FingerprintSource }) {
  const style = source === null ? UNFINGERPRINTED_STYLE : SOURCE_STYLES[source];
  const label = source === null ? "Unfingerprinted" : SOURCE_LABELS[source];

  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset ${style}`}
    >
      {label}
    </span>
  );
}
