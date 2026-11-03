import type { ValidationState } from "@/lib/types/finding";

/**
 * Same exhaustive-`Record` convention as `SeverityBadge.tsx`, but following
 * `FingerprintBadge.tsx`'s `Exclude<...>` shape instead: "unvalidated" is
 * the overwhelmingly common default for every Finding, so it must render
 * nothing, not a neutral "Unvalidated" badge that would just be noise on
 * every single finding row.
 */
const VALIDATION_STYLES: Record<Exclude<ValidationState, "unvalidated">, string> = {
  confirmed: "bg-emerald-100 text-emerald-700 ring-emerald-300",
  false_positive: "bg-zinc-200 text-zinc-600 ring-zinc-400",
};

const VALIDATION_LABELS: Record<Exclude<ValidationState, "unvalidated">, string> = {
  confirmed: "Confirmed",
  false_positive: "False Positive",
};

export default function ValidationBadge({ state }: { state: ValidationState }) {
  if (state === "unvalidated") return null;
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset ${VALIDATION_STYLES[state]}`}
    >
      {VALIDATION_LABELS[state]}
    </span>
  );
}
