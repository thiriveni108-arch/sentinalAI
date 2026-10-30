import type { RiskLevel } from "@/domain/sentinel";
import { severityClass } from "@/lib/presentation";
import { cn } from "@/lib/utils";

export function ThreatSeverity({ level }: { level: RiskLevel }) {
  return <span className={cn("threat-severity inline-flex w-fit items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wide", level === "Critical" && "is-critical", level === "High" && "is-high", severityClass[level])}><span aria-hidden="true" className="size-1.5 rounded-full bg-current" />{level}</span>;
}
