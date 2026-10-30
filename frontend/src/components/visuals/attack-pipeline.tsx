import { ArrowRight, Binary, Crosshair, FileInput, Microscope, ScanSearch } from "lucide-react";

const stages = [
  { label: "Normal behavior", detail: "Copied CERT user-day", icon: FileInput },
  { label: "Injected behavior", detail: "Bounded observable changes", icon: Crosshair },
  { label: "Model inference", detail: "Frozen preprocessing + models", icon: Binary },
  { label: "Detection outcome", detail: "Persisted alert or miss", icon: ScanSearch },
  { label: "Investigation", detail: "Evidence remains attached", icon: Microscope },
];

export function AttackPipeline() {
  return <section className="visual-lab panel p-5"><div className="tech-label">Controlled experiment pipeline</div><div className="attack-pipeline mt-5">{stages.map(({ label, detail, icon: Icon }, index) => <div key={label} className="contents"><article className="attack-stage"><span><Icon className="size-4" /></span><div><b>{label}</b><small>{detail}</small></div></article>{index < stages.length - 1 && <ArrowRight className="attack-flow-arrow size-4" />}</div>)}</div><p className="mt-4 text-[9px] text-[var(--text-muted)]">Every stage is backed by the supported persisted experiment. A detection miss remains a valid inspectable result.</p></section>;
}
