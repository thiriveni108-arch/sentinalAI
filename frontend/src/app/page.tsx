import Link from "next/link";
import { Activity, ArrowRight, Database, FlaskConical, SearchCheck, ShieldCheck, UsersRound } from "lucide-react";
import { getSentinelDataSource } from "@/data/data-source";

export default async function CommandCenter() {
  const source = getSentinelDataSource();
  const [cert, findings, legacy, models] = await Promise.all([
    source.getCertStatus(), source.listCertFindings({ pageSize: 6 }), source.getCounts(), source.listModels(),
  ]);
  const ready = models.filter((model) => model.status === "ready").length;
  return <div className="mx-auto max-w-[1580px] space-y-5">
    <header className="border-b border-border pb-5"><div className="tech-label">SentinelAI-Q / unified operations</div><div className="mt-2 flex flex-wrap items-end justify-between gap-4"><div><h1 className="text-[26px] font-bold tracking-[-.035em]">Command Center</h1><p className="mt-1 text-[12px] text-[var(--text-secondary)]">CERT behavioural monitoring, investigation and modeled response planning.</p></div><span className="rounded-full border border-[var(--low)]/40 bg-[var(--low)]/5 px-3 py-1.5 text-[10px] font-semibold text-[var(--low)]">RESEARCH ENVIRONMENT READY</span></div></header>
    <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
      <Stat icon={UsersRound} label="Available employees" value={cert.availableEmployees.toLocaleString()} note="CERT user IDs; no invented identity metadata" />
      <Stat icon={Database} label="Processed user-days" value={cert.processedUserDays.toLocaleString()} note={`${cert.dateCoverage.start} to ${cert.dateCoverage.end}`} />
      <Stat icon={SearchCheck} label="Stored QSVC findings" value={String(findings.page.total)} note={`${findings.scoringCoverage} balanced test rows scored`} />
      <Stat icon={Activity} label="Legacy alerts" value={String(legacy.alerts)} note="Synthetic event source; reported separately" />
      <Stat icon={ShieldCheck} label="Detection readiness" value={`${ready}/${models.length}`} note="QSVC advisory; SHIELD exact solver authoritative" />
    </section>
    <section className="grid gap-4 xl:grid-cols-[1.35fr_.65fr]">
      <article className="panel overflow-hidden"><div className="flex items-center justify-between border-b border-border p-4"><div><h2 className="text-sm font-semibold">Recent persisted QSVC findings</h2><p className="mt-1 text-[10px] text-[var(--text-muted)]">Bounded balanced benchmark results—not corpus-wide scoring.</p></div><Link href="/threats" className="text-[10px] font-semibold text-[var(--accent)]">Open monitor</Link></div><div className="divide-y divide-border">{findings.items.map((item) => <Link key={item.findingId} href={`/investigation?user=${item.user}&date=${item.date}&split=test`} className="flex items-center gap-4 px-4 py-3 hover:bg-[var(--surface-hover)]"><span className="size-2 rounded-full bg-[var(--high)]"/><span className="min-w-0 flex-1"><b className="font-mono text-[11px]">{item.user}</b><span className="ml-2 text-[10px] text-[var(--text-muted)]">{item.date} · {item.observedSignals.length} observed signal types</span></span><span className="font-mono text-[11px]">{item.decisionScore.toFixed(3)}</span><ArrowRight className="size-3.5 text-[var(--text-muted)]"/></Link>)}</div></article>
      <article className="panel p-5"><h2 className="text-sm font-semibold">Operational boundaries</h2><dl className="mt-4 space-y-4 text-[11px]"><Fact label="Primary source" value={cert.primaryDataset}/><Fact label="Entity" value={cert.entitySchema}/><Fact label="Natural prevalence" value={`${(cert.naturalPositiveRate * 100).toFixed(3)}% labelled malicious`}/><Fact label="QSVC" value="Advisory, uncalibrated decision score"/><Fact label="SHIELD" value="Modeled scenarios only; no automatic CERT graph"/></dl><Link href="/simulation" className="mt-5 inline-flex items-center gap-2 text-[11px] font-semibold text-[var(--accent)]"><FlaskConical className="size-3.5"/>Review evaluation evidence</Link></article>
    </section>
  </div>;
}
function Stat({icon:Icon,label,value,note}:{icon:typeof Activity;label:string;value:string;note:string}) { return <article className="panel p-4"><Icon className="size-4 text-[var(--accent)]"/><div className="mt-4 font-mono text-xl font-semibold">{value}</div><div className="mt-1 text-[11px] font-semibold">{label}</div><p className="mt-2 text-[9px] leading-4 text-[var(--text-muted)]">{note}</p></article> }
function Fact({label,value}:{label:string;value:string}) { return <div><dt className="tech-label">{label}</dt><dd className="mt-1 text-[var(--text-secondary)]">{value}</dd></div> }
