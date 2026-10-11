"use client";

import { Badge, StatusDot } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

/**
 * Scan status pill.
 *
 * The five states the operator asked for: Pending, Queued, Running,
 * Completed, Failed. `cancelled` is also handled because GitHub can cancel a
 * run.
 *
 * Note the deliberate distinction between "queued" (GitHub accepted our
 * dispatch) and "completed" (the engine actually ran and wrote results).
 */

export type ScanPhase =
  | "pending"
  | "dispatching"
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

const PHASE_META: Record<
  ScanPhase,
  { label: string; tone: "neutral" | "accent" | "ok" | "warn" | "bad"; pulse?: boolean }
> = {
  pending: { label: "Pending", tone: "neutral" },
  dispatching: { label: "Dispatching", tone: "accent", pulse: true },
  queued: { label: "Queued", tone: "accent", pulse: true },
  running: { label: "Running", tone: "accent", pulse: true },
  completed: { label: "Completed", tone: "ok" },
  failed: { label: "Failed", tone: "bad" },
  cancelled: { label: "Cancelled", tone: "warn" },
};

export function ScanStatusPill({
  status,
  className,
}: {
  status: ScanPhase;
  className?: string;
}) {
  const meta = PHASE_META[status] ?? PHASE_META.pending;
  return (
    <Badge variant={meta.tone} className={cn("gap-1.5", className)}>
      <StatusDot tone={meta.tone === "neutral" ? "neutral" : meta.tone} pulse={meta.pulse} />
      {meta.label}
    </Badge>
  );
}

/** Map a GitHub run state onto our phase vocabulary. */
export function phaseFromRun(
  status: string | null,
  conclusion: string | null,
): ScanPhase {
  if (status === "queued" || status === "waiting") return "queued";
  if (status === "in_progress") return "running";
  if (conclusion === "success") return "completed";
  if (conclusion === "cancelled") return "cancelled";
  if (conclusion) return "failed";
  return "pending";
}
