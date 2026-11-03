"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { updateFindingValidation } from "@/lib/api/findings";
import type { FindingRead, ValidationState } from "@/lib/types/finding";

/**
 * Compact inline form for setting one Finding's validation_state (+
 * optional note). Same refresh strategy as ScanCreateButton: call the
 * PATCH, then router.refresh() to re-fetch the server component's
 * getScanAssets() rather than reconciling local state with the server's.
 */
export default function FindingValidationControl({ finding }: { finding: FindingRead }) {
  const router = useRouter();
  const [state, setState] = useState<ValidationState>(finding.validation_state);
  const [note, setNote] = useState(finding.validation_note ?? "");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsSubmitting(true);
    setError(null);
    try {
      const result = await updateFindingValidation(finding.id, {
        validation_state: state,
        validation_note: note.trim() === "" ? null : note.trim(),
      });
      setState(result.validation_state);
      setNote(result.validation_note ?? "");
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update finding.");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-wrap items-center gap-1.5">
      <select
        value={state}
        onChange={(event) => setState(event.target.value as ValidationState)}
        disabled={isSubmitting}
        className="rounded border border-zinc-300 px-1.5 py-0.5 text-xs text-zinc-700 disabled:opacity-60"
      >
        <option value="unvalidated">Unvalidated</option>
        <option value="confirmed">Confirmed</option>
        <option value="false_positive">False Positive</option>
      </select>
      <input
        type="text"
        value={state === "unvalidated" ? "" : note}
        onChange={(event) => setNote(event.target.value)}
        disabled={isSubmitting || state === "unvalidated"}
        placeholder="Note (optional)"
        className="w-32 rounded border border-zinc-300 px-1.5 py-0.5 text-xs text-zinc-700 disabled:opacity-60"
      />
      <button
        type="submit"
        disabled={isSubmitting}
        className="rounded bg-zinc-900 px-2 py-0.5 text-xs font-medium text-white disabled:opacity-60"
      >
        Save
      </button>
      {error && <span className="text-xs text-red-600">{error}</span>}
    </form>
  );
}
