import Link from "next/link";
import { ChevronRight } from "lucide-react";
import type { UserSummary } from "@/domain/sentinel";
import { RiskValue } from "@/components/threats/risk-value";
import { ThreatSeverity } from "@/components/threats/threat-severity";

export function UserTable({ items }: { items: UserSummary[] }) {
  if (!items.length) return <div className="panel px-5 py-12 text-center text-[12px] text-[var(--text-muted)]">No users match the current filters.</div>;
  return (
    <div className="interactive-data-table panel overflow-x-auto scrollbar-thin">
      <table className="w-full min-w-[820px] border-collapse text-left">
        <caption className="sr-only">SentinelAI monitored users</caption>
        <thead className="border-b border-border bg-[var(--surface-elevated)] text-[9px] uppercase tracking-[0.1em] text-[var(--text-muted)]"><tr><th scope="col" className="px-3 py-2.5">User</th><th scope="col" className="px-3 py-2.5">Peer group</th><th scope="col" className="px-3 py-2.5">Latest risk</th><th scope="col" className="px-3 py-2.5">Activity</th><th scope="col" className="px-3 py-2.5">Alerts</th><th scope="col" className="px-3 py-2.5">Baseline</th><th scope="col"><span className="sr-only">Open user</span></th></tr></thead>
        <tbody className="divide-y divide-border">
          {items.map((item) => <tr key={item.employeeId} className="hover:bg-[var(--surface-hover)]">
            <td className="px-3 py-3"><Link href={`/users/${item.employeeId}`} className="text-[12px] font-semibold hover:text-[var(--accent-strong)]">{item.employeeName}</Link><span className="mt-0.5 block font-mono text-[10px] text-[var(--text-muted)]">{item.employeeId}</span></td>
            <td className="px-3 py-3 text-[11px]"><span className="block">{item.department}</span><span className="text-[var(--text-muted)]">{item.role}</span></td>
            <td className="px-3 py-3">{item.latestRiskLevel && item.latestRiskScore !== null ? <div className="flex items-center gap-3"><ThreatSeverity level={item.latestRiskLevel} /><RiskValue level={item.latestRiskLevel} score={item.latestRiskScore} /></div> : <span className="text-[var(--text-muted)]">No score</span>}</td>
            <td className="px-3 py-3 font-mono text-[11px] tabular">{item.activityCount}</td><td className="px-3 py-3 font-mono text-[11px] tabular">{item.alertCount}</td>
            <td className="px-3 py-3"><span className="font-mono text-[11px] tabular">{Math.round(item.profileConfidence * 100)}%</span><span className="ml-2 text-[10px] text-[var(--text-muted)]">{item.historyEventCount} events</span></td>
            <td className="px-3 py-3"><Link href={`/users/${item.employeeId}`} aria-label={`Open profile for ${item.employeeName}`} className="grid size-7 place-items-center rounded-sm text-[var(--text-muted)] hover:bg-[var(--surface-selected)] hover:text-foreground"><ChevronRight aria-hidden="true" className="size-3.5" /></Link></td>
          </tr>)}
        </tbody>
      </table>
    </div>
  );
}
