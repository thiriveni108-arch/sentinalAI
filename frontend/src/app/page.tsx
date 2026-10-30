import Link from "next/link";
import { Activity, ArrowRight, Database, FlaskConical, SearchCheck, ShieldCheck, UsersRound } from "lucide-react";
import { WorkflowBeam } from "@/components/incident/workflow-beam";
import { SpotlightCard } from "@/components/ui/spotlight-card";
import { getSentinelDataSource } from "@/data/data-source";

export default async function CommandCenter() {
  const source = getSentinelDataSource();
  const [cert, incidents, legacy, models] = await Promise.all([
    source.getCertStatus(), source.listIncidents(), source.getCounts(), source.listModels(),
  ]);
  const ready = models.filter((model) => model.status === "ready").length;

  return <div className="mx-auto max-w-[1580px] space-y-5">
    <header className="border-b border-border pb-5">
      <div className="tech-label">SentinelAI-Q / connected defense operations</div>
      <div className="mt-2 flex flex-wrap items-end justify-between gap-4">
        <div><h1 className="text-[26px] font-bold tracking-[-.035em]">Command Center</h1><p className="mt-1 text-[12px] text-[var(--text-secondary)]">ATTACK → DETECT → INVESTIGATE → OPTIMIZE → VERIFY → REVIEW</p></div>
        <span className="rounded-full border border-[var(--low)]/40 bg-[var(--low)]/5 px-3 py-1.5 text-[10px] font-semibold text-[var(--low)]">RESEARCH ENVIRONMENT READY</span>
      </div>
    </header>
    <WorkflowBeam />
    <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
      <Stat icon={UsersRound} label="Available identities" value={cert.availableEmployees.toLocaleString()} note="CERT pseudonymous population" />
      <Stat icon={Database} label="Processed user-days" value={cert.processedUserDays.toLocaleString()} note={`${cert.dateCoverage.start} to ${cert.dateCoverage.end}`} />
      <Stat icon={SearchCheck} label="Connected incidents" value={String(incidents.summary.total)} note={`${incidents.summary.detected} detected · ${incidents.summary.responsePlanned} response planned`} />
      <Stat icon={Activity} label="Legacy alerts" value={String(legacy.alerts)} note="Synthetic event source, kept separate" />
      <Stat icon={ShieldCheck} label="Model readiness" value={`${ready}/${models.length}`} note="Frozen detection and verified response" />
    </section>
    <section className="grid gap-4 xl:grid-cols-[1.35fr_.65fr]">
      <SpotlightCard className="overflow-hidden" glowColor="blue">
        <div className="flex items-center justify-between border-b border-border p-4"><div><h2 className="text-sm font-semibold">Recent connected incidents</h2><p className="mt-1 text-[10px] text-[var(--text-muted)]">Persisted controlled CERT exercises—not fake live activity.</p></div><Link href="/attack-lab" className="text-[10px] font-semibold text-[var(--accent)]">Open Adversary Lab</Link></div>
        <div className="incident-list divide-y divide-border">{incidents.items.length ? incidents.items.slice(0, 6).map((item) => <Link key={item.incidentId} href={`/investigation?incident=${item.incidentId}`} className="incident-row flex items-center gap-4 px-4 py-3"><span className={`incident-signal size-2 rounded-full ${item.detection.findingCreated ? "bg-[var(--high)]" : "bg-[var(--medium)]"}`} /><span className="min-w-0 flex-1"><b className="identity-name text-[11px]">{item.canonicalRecord.identity.displayLabel}</b><span className="ml-2 font-mono text-[9px] text-[var(--text-muted)]">{item.incidentId} · {item.detection.outcome.replaceAll("_", " ")}</span></span><span className="text-[9px]">{item.shield.status.replaceAll("_", " ")}</span><ArrowRight className="incident-arrow size-3.5 text-[var(--text-muted)]" /></Link>) : <div className="p-8 text-center text-[11px] text-[var(--text-muted)]">No connected incidents yet. Start in Adversary Lab.</div>}</div>
      </SpotlightCard>
      <SpotlightCard className="p-5" glowColor="purple">
        <h2 className="text-sm font-semibold">Operational boundaries</h2>
        <dl className="mt-4 space-y-4 text-[11px]"><Fact label="Primary source" value={cert.primaryDataset} /><Fact label="Assessment policy" value={cert.assessmentPolicy?.selectedPolicy.replaceAll("_", " ") ?? "Unavailable"} /><Fact label="Scores" value="Raw, uncalibrated decision values" /><Fact label="SHIELD" value="Hypothetical incident graphs; exact solver authoritative" /></dl>
        <Link href="/simulation?tab=evaluation" className="mt-5 inline-flex items-center gap-2 text-[11px] font-semibold text-[var(--accent)]"><FlaskConical className="size-3.5" />Open Model Validation</Link>
      </SpotlightCard>
    </section>
  </div>;
}

function Stat({ icon: Icon, label, value, note }: { icon: typeof Activity; label: string; value: string; note: string }) {
  return <SpotlightCard className="stat-glow-card p-4" glowColor="blue"><Icon className="size-4 text-[var(--accent)]" /><div className="mt-4 font-mono text-xl font-semibold">{value}</div><div className="mt-1 text-[11px] font-semibold">{label}</div><p className="mt-2 text-[9px] leading-4 text-[var(--text-muted)]">{note}</p></SpotlightCard>;
}

function Fact({ label, value }: { label: string; value: string }) {
  return <div><dt className="tech-label">{label}</dt><dd className="mt-1 text-[var(--text-secondary)]">{value}</dd></div>;
}
