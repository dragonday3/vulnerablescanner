"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { createScan } from "@/lib/api/scans";
import type { TargetRead } from "@/lib/types/target";

/**
 * Small inline form: pick one of the project's targets, then create a scan
 * against it. Same refresh strategy as `ProjectForm`/`TargetForm` (Task 11):
 * `router.refresh()` after a successful create re-runs the server
 * component's `listScans()` fetch rather than duplicating scan-list state
 * on the client.
 */
export default function ScanCreateButton({
  projectId,
  targets,
}: {
  projectId: string;
  targets: TargetRead[];
}) {
  const router = useRouter();
  // The backend rejects a scan against an unauthorized target with a 400
  // (scan_service.create_scan's defense-in-depth check), so offering those
  // targets here would just be a confusing dead end — this page already
  // shows a "Not authorized" badge for the exact same target above. Filter
  // to authorized-only before anything below reads `targets`.
  const authorizedTargets = targets.filter((target) => target.authorization_confirmed === true);

  const [targetId, setTargetId] = useState(authorizedTargets[0]?.id ?? "");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const hasTargets = authorizedTargets.length > 0;

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!targetId) {
      setError("Select a target first.");
      return;
    }

    setIsSubmitting(true);
    setError(null);
    try {
      await createScan({ project_id: projectId, target_id: targetId });
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create scan.");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="flex flex-col gap-4 rounded-lg border border-zinc-200 bg-white p-6 shadow-sm"
    >
      <h2 className="text-lg font-semibold text-zinc-900">New scan</h2>

      {hasTargets ? (
        <>
          <div className="flex flex-col gap-1">
            <label htmlFor="scan-target" className="text-sm font-medium text-zinc-700">
              Target
            </label>
            <select
              id="scan-target"
              name="target_id"
              value={targetId}
              onChange={(event) => setTargetId(event.target.value)}
              disabled={isSubmitting}
              className="rounded-md border border-zinc-300 px-3 py-2 text-sm text-zinc-900 focus:border-zinc-500 focus:outline-none disabled:opacity-60"
            >
              {authorizedTargets.map((target) => (
                <option key={target.id} value={target.id}>
                  {target.value} ({target.target_type})
                </option>
              ))}
            </select>
          </div>

          {error && <p className="text-sm text-red-600">{error}</p>}

          <button
            type="submit"
            disabled={isSubmitting}
            className="self-start rounded-md bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-700 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isSubmitting ? "Starting..." : "Start scan"}
          </button>
        </>
      ) : targets.length === 0 ? (
        <p className="text-sm text-zinc-500">
          Add a target above before starting a scan.
        </p>
      ) : (
        <p className="text-sm text-zinc-500">
          This project has targets, but none are authorized for scanning yet. Confirm
          authorization on a target above before starting a scan.
        </p>
      )}
    </form>
  );
}
