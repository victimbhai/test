import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium whitespace-nowrap",
  {
    variants: {
      variant: {
        neutral:
          "border-[var(--border-strong)] bg-[var(--surface-raised)] text-[var(--muted)]",
        accent:
          "border-accent-500/40 bg-accent-500/10 text-accent-300",
        ok: "border-ok-500/40 bg-ok-500/10 text-ok-400",
        warn: "border-warn-500/40 bg-warn-500/10 text-warn-400",
        bad: "border-bad-500/40 bg-bad-500/10 text-bad-400",
      },
    },
    defaultVariants: { variant: "neutral" },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <span className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

/** Small coloured dot used inside status pills. */
export function StatusDot({
  tone = "neutral",
  pulse = false,
}: {
  tone?: "neutral" | "accent" | "ok" | "warn" | "bad";
  pulse?: boolean;
}) {
  const colors: Record<string, string> = {
    neutral: "bg-[var(--muted)]",
    accent: "bg-accent-400",
    ok: "bg-ok-400",
    warn: "bg-warn-400",
    bad: "bg-bad-400",
  };

  return (
    <span
      className={cn(
        "inline-block h-1.5 w-1.5 shrink-0 rounded-full",
        colors[tone],
        pulse && "pulse-ring",
      )}
      aria-hidden="true"
    />
  );
}

export { Badge, badgeVariants };
