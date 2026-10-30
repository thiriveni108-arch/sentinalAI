import Link from "next/link";
import type { ActivityRecord } from "@/domain/sentinel";
import { RiskValue } from "@/components/threats/risk-value";
import { ThreatSeverity } from "@/components/threats/threat-severity";

function readable(value: string) { return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()); }
function timestamp(value: string) { return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(new Date(value)); }

export function ActivityTable({ items }: { items: ActivityRecord[] }) {
  if (!items.length) return <div className="panel px-5 py-12 text-center text-[12px] text-[var(--text-muted)]">No activity matches the current filters.</div>;
  return (
    <div className="interactive-data-table panel overflow-x-auto scrollbar-thin">
      <table className="w-full min-w-[940px] border-collapse text-left">
        <caption className="sr-only">Persisted SentinelAI activity events</caption>
        <thead className="border-b border-border bg-[var(--surface-elevated)] text-[9px] uppercase tracking-[0.1em] text-[var(--text-muted)]">
          <tr><th scope="col" className="px-3 py-2.5">Risk</th><th scope="col" className="px-3 py-2.5">Event</th><th scope="col" className="px-3 py-2.5">Employee</th><th scope="col" className="px-3 py-2.5">Activity</th><th scope="col" className="hidden px-3 py-2.5 xl:table-cell">Context</th><th scope="col" className="px-3 py-2.5">Timestamp</th><th scope="col" className="px-3 py-2.5">Alert</th></tr>
        </thead>
        <tbody className="divide-y divide-border">
          {items.map((item) => (
            <tr key={item.eventId} className="align-top hover:bg-[var(--surface-hover)]">
              <td className="px-3 py-3">{item.riskLevel && item.riskScore !== null ? <div className="space-y-1.5"><ThreatSeverity level={item.riskLevel} /><div><RiskValue level={item.riskLevel} score={item.riskScore} /></div></div> : <span className="text-[var(--text-muted)]">—</span>}</td>
              <td className="px-3 py-3"><Link href={`/activity/${encodeURIComponent(item.eventId)}`} className="font-mono text-[10px] text-[var(--text-secondary)] hover:text-[var(--accent-strong)]">{item.eventId}</Link>{item.simulationId && <span className="mt-1 block font-mono text-[9px] text-[var(--accent-strong)]">RUN {item.simulationId}</span>}</td>
              <td className="px-3 py-3"><Link href={`/users/${item.employeeId}`} className="text-[12px] font-medium hover:text-[var(--accent-strong)]">{item.employeeName}</Link><span className="mt-0.5 block text-[10px] text-[var(--text-muted)]">{item.employeeId} · {item.department}</span></td>
              <td className="px-3 py-3"><span className="text-[12px] font-medium">{readable(item.activityType)}</span><span className="mt-0.5 block text-[10px] text-[var(--text-muted)]">{readable(item.scenario)}</span>{item.resourceName && <span className="mt-1 block max-w-56 truncate text-[10px] text-[var(--text-secondary)]">{item.resourceName} · {item.resourceSensitivity}</span>}</td>
              <td className="hidden px-3 py-3 text-[10px] xl:table-cell">
                <div className="space-y-1.5">
                  <div className="flex flex-wrap gap-1">
                    <span className="rounded border border-[var(--border)] bg-[var(--surface-elevated)] px-1.5 py-0.5 text-[9px] font-mono text-[var(--text-secondary)]">dev:{item.deviceId}</span>
                    <span className="rounded border border-[var(--border)] bg-[var(--surface-elevated)] px-1.5 py-0.5 text-[9px] font-mono text-[var(--text-secondary)]">ip:{item.ipAddress}</span>
                  </div>
                  <div className="inline-flex rounded border border-[var(--border)] bg-[var(--surface-elevated)] px-1.5 py-0.5 text-[9px] text-[var(--text-secondary)]">
                    loc:{item.city}, {item.country}
                  </div>
                </div>
              </td>
              <td className="px-3 py-3 font-mono text-[10px] text-[var(--text-secondary)]">{timestamp(item.occurredAt)}<span className="mt-1 block text-[var(--text-muted)]">UTC</span></td>
              <td className="px-3 py-3">{item.alertId ? <Link href={`/threats?focus=${encodeURIComponent(item.alertId)}`} className="font-mono text-[10px] text-[var(--accent-strong)] hover:text-foreground">{item.alertId}</Link> : <span className="text-[var(--text-muted)]">—</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
