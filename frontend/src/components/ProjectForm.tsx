"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { createProject } from "@/lib/api/projects";

/**
 * Controlled create-project form.
 *
 * Refresh strategy: after a successful `createProject` call we invoke
 * `router.refresh()` rather than keeping a parallel client-side list in
 * local state. The `/projects` page is a server component that fetches the
 * list via `listProjects()`; `router.refresh()` re-runs that server fetch
 * (uncached by default, per Next.js's App Router fetch semantics) and
 * re-renders the page with the new data, so there is a single source of
 * truth for "the list of projects" instead of duplicating fetch/merge logic
 * on the client. The trade-off is a network round-trip on every submit
 * instead of an optimistic local update, which is an acceptable cost for
 * this simple form.
 */
export default function ProjectForm() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const trimmedName = name.trim();
    if (!trimmedName) {
      setError("Name is required.");
      return;
    }

    setIsSubmitting(true);
    setError(null);
    try {
      await createProject({
        name: trimmedName,
        description: description.trim() || null,
      });
      setName("");
      setDescription("");
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create project.");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="flex flex-col gap-4 rounded-lg border border-zinc-200 bg-white p-6 shadow-sm"
    >
      <h2 className="text-lg font-semibold text-zinc-900">New project</h2>

      <div className="flex flex-col gap-1">
        <label htmlFor="project-name" className="text-sm font-medium text-zinc-700">
          Name
        </label>
        <input
          id="project-name"
          name="name"
          type="text"
          value={name}
          onChange={(event) => setName(event.target.value)}
          required
          disabled={isSubmitting}
          className="rounded-md border border-zinc-300 px-3 py-2 text-sm text-zinc-900 focus:border-zinc-500 focus:outline-none disabled:opacity-60"
          placeholder="Acme Corp Pentest"
        />
      </div>

      <div className="flex flex-col gap-1">
        <label
          htmlFor="project-description"
          className="text-sm font-medium text-zinc-700"
        >
          Description
        </label>
        <textarea
          id="project-description"
          name="description"
          value={description}
          onChange={(event) => setDescription(event.target.value)}
          disabled={isSubmitting}
          rows={3}
          className="rounded-md border border-zinc-300 px-3 py-2 text-sm text-zinc-900 focus:border-zinc-500 focus:outline-none disabled:opacity-60"
          placeholder="Q4 authorized engagement"
        />
      </div>

      {error && <p className="text-sm text-red-600">{error}</p>}

      <button
        type="submit"
        disabled={isSubmitting}
        className="self-start rounded-md bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-700 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {isSubmitting ? "Creating..." : "Create project"}
      </button>
    </form>
  );
}
