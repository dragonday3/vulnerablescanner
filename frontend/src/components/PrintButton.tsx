"use client";

/**
 * Minimal client component (Phase 8) triggering the browser's native print
 * dialog — used on the report page, alongside `print:hidden` on navigation
 * links/buttons, so the printed/exported view shows just the report content.
 */
export default function PrintButton() {
  return (
    <button
      type="button"
      onClick={() => window.print()}
      className="rounded-md border border-zinc-300 bg-white px-3 py-1.5 text-sm font-medium text-zinc-700 shadow-sm hover:bg-zinc-50"
    >
      Print / Export PDF
    </button>
  );
}
