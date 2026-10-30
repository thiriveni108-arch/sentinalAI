"use client";

import type { CSSProperties } from "react";
import { Activity, CheckCircle2, Crosshair, ScanSearch, ShieldCheck, Sparkles } from "lucide-react";
import { useIncident } from "./incident-context";

const steps = [
  { label: "Detect", icon: Crosshair }, { label: "Investigate", icon: ScanSearch },
  { label: "Plan", icon: Sparkles }, { label: "Authorize", icon: ShieldCheck },
  { label: "Verify", icon: Activity }, { label: "Review", icon: CheckCircle2 },
];

function indexFor(status?: string) {
  if (!status) return 0;
  if (status === "INVESTIGATING") return 1;
  if (status.startsWith("PENDING")) return 3;
  if (["AUTHORIZED", "AUTO_AUTHORIZED", "READY"].includes(status)) return 3;
  if (["EXECUTING", "VERIFYING", "RECOVERY_PENDING"].includes(status)) return 4;
  return 5;
}

export function WorkflowBeam() {
  const { session } = useIncident();
  const active = indexFor(session?.lifecycle_status);
  return <section className="workflow-beam panel" aria-label="Connected incident workflow">
    <div className="workflow-beam-copy"><div className="tech-label">Connected response fabric</div><h2>{session ? "Incident context is moving with every decision" : "One continuous defense workflow"}</h2><p>{session ? `${session.context.identity.display_label} · ${session.lifecycle_status.replaceAll("_", " ").toLowerCase()}` : "Evidence, authority, execution, and recovery stay connected."}</p></div>
    <div className="workflow-track" style={{ "--workflow-progress": `${active / (steps.length - 1) * 100}%` } as CSSProperties}>
      <span className="workflow-line" aria-hidden="true" /><span className="workflow-progress" aria-hidden="true" /><span className="workflow-pulse" aria-hidden="true" />
      {steps.map(({ label, icon: Icon }, index) => <div key={label} className={`workflow-node ${index < active ? "is-complete" : index === active ? "is-active" : ""}`}><span><Icon className="size-3.5" /></span><b>{label}</b></div>)}
    </div>
  </section>;
}
