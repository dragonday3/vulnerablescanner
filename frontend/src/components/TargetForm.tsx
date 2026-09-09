"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { createTarget } from "@/lib/api/targets";
import type { TargetType } from "@/lib/types/target";

const TARGET_TYPES: TargetType[] = ["ip", "domain", "hostname", "cidr"];

/**
 * Create-target form for a project. Mirrors `ProjectForm`'s refresh
 * strategy (Task 11): calls `createTarget`, then `router.refresh()` so the
 * server-rendered target list on `/projects/[projectId]` re-fetches instead
 * of duplicating list state on the client.
 *
 * `authorization_confirmed` mirrors the backend's 422 rejection on
 * unauthorized targets: the checkbox must be checked before the form can
 * be submitted at all (submit button stays disabled and a validation
 * message is shown until then), rather than letting the request round-trip
 * to the backend just to be rejected.
 */
export default function TargetForm({ projectId }: { projectId: string }) {
  const router = useRouter();
  const [value, setValue] = useState("");
  const [targetType, setTargetType] = useState<TargetType>("domain");
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSubmit = value.trim().length > 0 && authorizationConfirmed;

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const trimmedValue = value.trim();
    if (!trimmedValue) {
      setError("Value is required.");
      return;
    }
    if (!authorizationConfirmed) {
      setError("You must confirm authorization to scan this target.");
      return;
    }

    setIsSubmitting(true);
    setError(null);
    try {
      await createTarget(projectId, {
        value: trimmedValue,
        target_type: targetType,
        authorization_confirmed: authorizationConfirmed,
      });
      setValue("");
      setTargetType("domain");
      setAuthorizationConfirmed(false);
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create target.");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="flex flex-col gap-4 rounded-lg border border-zinc-200 bg-white p-6 shadow-sm"
    >
      <h2 className="text-lg font-semibold text-zinc-900">New target</h2>

      <div className="flex flex-col gap-1">
        <label htmlFor="target-value" className="text-sm font-medium text-zinc-700">
          Value
        </label>
        <input
          id="target-value"
          name="value"
          type="text"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          required
          disabled={isSubmitting}
          className="rounded-md border border-zinc-300 px-3 py-2 text-sm text-zinc-900 focus:border-zinc-500 focus:outline-none disabled:opacity-60"
          placeholder="example.com"
        />
      </div>

      <div className="flex flex-col gap-1">
        <label htmlFor="target-type" className="text-sm font-medium text-zinc-700">
          Type
        </label>
        <select
          id="target-type"
          name="target_type"
          value={targetType}
          onChange={(event) => setTargetType(event.target.value as TargetType)}
          disabled={isSubmitting}
          className="rounded-md border border-zinc-300 px-3 py-2 text-sm text-zinc-900 focus:border-zinc-500 focus:outline-none disabled:opacity-60"
        >
          {TARGET_TYPES.map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </select>
      </div>

      <label className="flex items-start gap-2 text-sm text-zinc-700">
        <input
          type="checkbox"
          name="authorization_confirmed"
          checked={authorizationConfirmed}
          onChange={(event) => setAuthorizationConfirmed(event.target.checked)}
          disabled={isSubmitting}
          className="mt-0.5"
        />
        <span>
          I confirm I am authorized to scan this target.
        </span>
      </label>
      {!authorizationConfirmed && (
        <p className="text-sm text-amber-600">
          You must confirm authorization before this target can be added.
        </p>
      )}

      {error && <p className="text-sm text-red-600">{error}</p>}

      <button
        type="submit"
        disabled={isSubmitting || !canSubmit}
        className="self-start rounded-md bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-700 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {isSubmitting ? "Adding..." : "Add target"}
      </button>
    </form>
  );
}
