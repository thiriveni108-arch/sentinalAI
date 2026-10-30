import type { Metadata } from "next";
import { AttackLabSubmitButton } from "@/components/attack-lab/submit-button";
import { getSentinelDataSource } from "@/data/data-source";
import { createAttackLabRun, createCertIncident } from "./actions";
import { AttackPipeline } from "@/components/visuals/attack-pipeline";

export const metadata: Metadata = { title: "Attack Lab" };
type SearchParams = Promise<Record<string, string | string[] | undefined>>;
function scalar(value: string | string[] | undefined) { return Array.isArray(value) ? value[0] : value; }

export default async function AttackLabPage({ searchParams }: { searchParams: SearchParams }) {
  const source = getSentinelDataSource();
  const [scenarios, users, certRecords, incidents, params] = await Promise.all([source.listAttackLabScenarios(), source.listUsers({ pageSize: 100 }), source.listCertFindings({ prediction: 0, pageSize: 20 }), source.listIncidents(), searchParams]);
  const live = source.mode === "http";
  const certReady = certRecords.items.length > 0;
  const error = scalar(params.error);
  const message = error === "live_api_required" ? "Attack Lab execution requires live API mode." : error ? "The run could not be created. Verify the inputs and API status." : null;
  return <div className="mx-auto max-w-[1300px] space-y-6">
    <section className="border-b border-border pb-5"><div className="tech-label">Adversary Lab / controlled CERT exercise</div><h1 className="mt-2 text-[24px] font-bold tracking-[-0.03em]">Create a connected incident</h1><p className="mt-1 max-w-3xl text-[12px] text-[var(--text-secondary)]">Inject supported file-collection behavior into a copied CERT employee-day, execute all frozen detectors, and persist one incident across investigation, SHIELD, and observability.</p></section>
    {!live && <div role="status" className="border border-[var(--medium)]/40 bg-[var(--medium)]/5 px-4 py-3 text-[11px] text-[var(--text-secondary)]"><span className="font-semibold text-[var(--medium)]">LIVE API REQUIRED</span> · Set <code className="font-mono text-foreground">SENTINEL_DATA_SOURCE=http</code> to execute and persist a run. Scenario definitions remain visible offline.</div>}
    {message && <div role="alert" className="border border-[var(--critical)]/40 bg-[var(--critical)]/5 px-4 py-3 text-[11px] text-[var(--critical)]">{message}</div>}
    <AttackPipeline />
    <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_390px]">
      <article className="panel p-5"><div className="tech-label">Primary environment</div><h2 className="mt-2 text-lg font-semibold">Suspicious File Collection</h2><p className="mt-2 text-[11px] leading-5 text-[var(--text-secondary)]">Adds bounded removable-media and after-hours file indicators to a copy, maintains file subtype consistency, recomputes PCA with frozen training preprocessing, then runs QSVC, VQC, RBF-SVM, and transparent rules.</p><div className="mt-5 grid gap-3 sm:grid-cols-3"><Fact label="Source" value="CERT r4.2 user-day"/><Fact label="Mutation" value="Copy only"/><Fact label="Policy" value="QSVC LEAD"/></div><p className="mt-4 rounded-lg bg-[var(--surface-elevated)] p-3 text-[10px] text-[var(--text-muted)]">The exercise does not reconstruct raw events, change the research label, or guarantee detection. Misses remain persisted and inspectable.</p></article>
      <form action={createCertIncident} className="panel p-5">
        <div className="tech-label">New persistent run</div>
        <label className="mt-4 block"><span className="mb-1.5 block text-[10px] font-medium">Baseline employee-day</span><select name="record" required disabled={!certReady} className="control w-full px-3 disabled:cursor-not-allowed disabled:opacity-60">{certReady ? certRecords.items.map(record=><option key={record.findingId} value={`${record.user}|${record.date}`}>{record.identity.displayLabel} · {record.date} · {record.identity.sourceId}</option>) : <option>CERT benchmark cohort unavailable</option>}</select></label>
        <button disabled={!live || !certReady} className="mt-4 w-full rounded-lg bg-[var(--accent)] px-4 py-3 text-xs font-semibold text-white disabled:cursor-not-allowed disabled:opacity-40">Inject and run detection</button>
        <p className="mt-3 text-[9px] leading-4 text-[var(--text-muted)]">{certReady ? "Inference executes once. Subsequent navigation reads the persisted incident." : "Install the processed CERT benchmark cohort to create new runs. Existing persisted incidents remain available below."}</p>
      </form>
    </section>
    {incidents.items.length>0&&<section className="panel overflow-hidden"><div className="border-b border-border p-4"><h2 className="text-sm font-semibold">Recent connected incidents</h2></div><div className="divide-y divide-border">{incidents.items.slice(0,6).map(item=><a key={item.incidentId} href={`/investigation?incident=${item.incidentId}`} className="flex items-center justify-between gap-4 p-4 hover:bg-[var(--surface-hover)]"><div><b className="text-xs">{item.canonicalRecord.identity.displayLabel}</b><p className="mt-1 font-mono text-[9px] text-[var(--text-muted)]">{item.incidentId} · {item.canonicalRecord.date}</p></div><span className={`text-[10px] font-bold ${item.detection.findingCreated?"text-[var(--high)]":"text-[var(--medium)]"}`}>{item.detection.outcome.replaceAll("_"," ")}</span></a>)}</div></section>}
    <details className="panel p-5"><summary className="cursor-pointer text-sm font-semibold">Legacy synthetic event lab</summary><div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
      <section aria-labelledby="scenario-catalog" className="space-y-3"><div><div className="tech-label">Deterministic catalog</div><h2 id="scenario-catalog" className="mt-1 text-[14px] font-semibold">Available sequences</h2></div><div className="grid gap-3 sm:grid-cols-2">{scenarios.map((scenario) => <article key={scenario.scenario} className="panel p-4"><div className="flex items-start justify-between gap-3"><h3 className="text-[12px] font-semibold">{scenario.label}</h3><span className="rounded-sm border border-[var(--border-strong)] px-1.5 py-0.5 font-mono text-[9px] text-[var(--text-muted)]">{scenario.eventCount} EVENTS</span></div><p className="mt-2 text-[11px] leading-5 text-[var(--text-secondary)]">{scenario.description}</p><code className="mt-3 block font-mono text-[9px] text-[var(--text-muted)]">{scenario.scenario}</code></article>)}</div></section>
      <section className="panel h-fit p-4"><div className="tech-label">New run</div><h2 className="mt-1 text-[14px] font-semibold">Execution parameters</h2><form action={createAttackLabRun} className="mt-5 space-y-4">
        <label className="block"><span className="mb-1.5 block text-[10px] font-medium text-[var(--text-secondary)]">Employee</span><select required name="employeeId" className="control w-full px-3">{users.items.map((user) => <option key={user.employeeId} value={user.employeeId}>{user.employeeName} · {user.employeeId}</option>)}</select></label>
        <label className="block"><span className="mb-1.5 block text-[10px] font-medium text-[var(--text-secondary)]">Scenario</span><select required name="scenario" className="control w-full px-3">{scenarios.map((scenario) => <option key={scenario.scenario} value={scenario.scenario}>{scenario.label}</option>)}</select></label>
        <label className="block"><span className="mb-1.5 block text-[10px] font-medium text-[var(--text-secondary)]">Start time</span><input required type="datetime-local" name="startTime" defaultValue="2025-07-01T12:00" className="control w-full px-3" /></label>
        <label className="block"><span className="mb-1.5 block text-[10px] font-medium text-[var(--text-secondary)]">Intensity</span><select required name="intensity" className="control w-full px-3"><option value="standard">Standard</option><option value="elevated">Elevated</option></select></label>
        <p className="text-[10px] leading-4 text-[var(--text-muted)]">Intensity changes observable event values only. It does not introduce a new risk formula.</p>
        <AttackLabSubmitButton disabled={!live} />
      </form></section>
    </div></details>
  </div>;
}

function Fact({label,value}:{label:string;value:string}) { return <div className="rounded-lg bg-[var(--surface-elevated)] p-3"><div className="tech-label">{label}</div><div className="mt-2 text-xs font-semibold">{value}</div></div> }
