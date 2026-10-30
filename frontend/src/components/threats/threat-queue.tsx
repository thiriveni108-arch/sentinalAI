import Link from "next/link";
import type { ThreatSummary } from "@/domain/sentinel";
import { formatThreatTimestamp } from "@/lib/presentation";
import { cn } from "@/lib/utils";
import { RiskValue } from "./risk-value";
import { ThreatSeverity } from "./threat-severity";

export function ThreatQueue({ threats, compact = false, focusedId }: { threats: ThreatSummary[]; compact?: boolean; focusedId?: string }) {
  if (!threats.length) {
    return <div role="status" className="panel px-5 py-14 text-center text-[var(--text-muted)]">No alerts match the current filters.</div>;
  }

  return (
    <div className="interactive-data-table panel overflow-hidden">
      <div className="scrollbar-thin overflow-x-auto">
        <table className="w-full min-w-[960px] table-fixed border-collapse text-left">
          <caption className="sr-only">{compact ? "Highest-risk active alerts" : "Filtered active alert queue"}</caption>
          <colgroup>
            <col className="w-[88px]" /><col className="w-[21%]" /><col className="w-[16%]" /><col className="w-[76px]" /><col className="w-[30%]" /><col className="w-[120px]" /><col className="w-[94px]" />
          </colgroup>
          <thead className="bg-[var(--surface-elevated)]">
            <tr className="border-b border-border">
              {['Severity','Threat','Employee','Risk','Primary evidence','Timestamp','Status'].map((label) => <th key={label} scope="col" className="h-9 px-3 tech-label">{label}</th>)}
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {threats.map((threat) => {
              const occurred = formatThreatTimestamp(threat.occurredAt);
              const focused = threat.alertId === focusedId;
              return (
                <tr id={threat.alertId} key={threat.alertId} className={cn("h-16 transition-colors hover:bg-[var(--surface-hover)]", threat.riskLevel === "Critical" && "critical-threat-row", threat.riskLevel === "High" && "high-threat-row", focused && "bg-[var(--surface-selected)]")}>
                  <td className="px-3 py-2 align-middle"><ThreatSeverity level={threat.riskLevel} /></td>
                  <th scope="row" className="min-w-0 px-3 py-2 align-middle font-normal">
                    <Link aria-current={focused ? "location" : undefined} href={`/threats?focus=${encodeURIComponent(threat.alertId)}#${encodeURIComponent(threat.alertId)}`} className="block rounded-sm text-[12px] font-semibold text-foreground hover:text-[var(--accent-strong)] focus-visible:text-[var(--accent-strong)]">
                      <span className="block truncate">{threat.title}</span>
                      <span className="mt-1 block truncate font-mono text-[10px] font-normal text-[var(--text-muted)]">{threat.alertId}<span className="hidden 2xl:inline"> · {threat.story}</span></span>
                    </Link>
                  </th>
                  <td className="min-w-0 px-3 py-2 align-middle">
                    <span className="block truncate text-[12px] font-medium">{threat.employeeName}</span>
                    <span className="mt-1 block truncate font-mono text-[10px] text-[var(--text-muted)]">{threat.employeeId}<span className="hidden min-[1440px]:inline"> · {threat.department}</span></span>
                  </td>
                  <td className="px-3 py-2 align-middle"><RiskValue level={threat.riskLevel} score={threat.riskScore} /></td>
                  <td className="min-w-0 px-3 py-2 align-middle">
                    {threat.primaryEvidence ? <>
                      <span className="block truncate text-[11px] text-[var(--text-secondary)]">{threat.primaryEvidence.reason}</span>
                      <span className="mt-1 block truncate font-mono text-[9px] text-[var(--text-muted)]">{threat.primaryEvidence.code}<span className="hidden min-[1440px]:inline"> · {threat.primaryEvidence.observed} / expected {threat.primaryEvidence.expected}</span></span>
                    </> : <span className="text-[11px] text-[var(--text-muted)]">No rule evidence persisted</span>}
                  </td>
                  <td className="px-3 py-2 align-middle font-mono text-[10px] text-[var(--text-secondary)]" aria-label={occurred.full}><span className="block">{occurred.date}</span><span className="mt-1 block text-[var(--text-muted)]">{occurred.time} IST</span></td>
                  <td className="px-3 py-2 align-middle"><span className="inline-flex items-center gap-1.5 text-[11px] text-[var(--text-secondary)]"><span aria-hidden="true" className="size-1.5 rounded-full bg-[var(--text-muted)]" />{threat.status}</span></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {!compact && <div className="border-t border-border px-3 py-2.5 font-mono text-[10px] text-[var(--text-muted)]">{threats.length} alerts shown · persisted risk order</div>}
    </div>
  );
}
