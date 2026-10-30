"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Expand, X } from "lucide-react";
import * as echarts from "echarts/core";
import { LineChart } from "echarts/charts";
import { DataZoomComponent, GraphicComponent, GridComponent, LegendComponent, TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import type { CertIncident, CertMonthlyActivity, IncidentList } from "@/domain/sentinel";

echarts.use([LineChart, DataZoomComponent, GraphicComponent, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer]);

const SERIES = [
  { key: "login", name: "Logon", color: "#2563eb" },
  { key: "email", name: "Email", color: "#7c3aed" },
  { key: "file", name: "File", color: "#0891b2" },
  { key: "removableMedia", name: "Removable media", color: "#d97706" },
] as const;

export function CertActivityTimeline({ activity }: { activity: CertMonthlyActivity }) {
  const host = useRef<HTMLDivElement>(null);
  const [range, setRange] = useState<6 | 12 | "all">("all");
  const points = useMemo(() => range === "all" ? activity.points : activity.points.slice(-range), [activity.points, range]);
  const option = useCallback((): echarts.EChartsCoreOption => ({
    animationDuration: 850,
    animationEasing: "cubicOut",
    color: SERIES.map((series) => series.color),
    grid: { left: 60, right: 24, top: 58, bottom: 50 },
    legend: { top: 5, left: 0, selectedMode: true, icon: "roundRect", itemWidth: 18, itemHeight: 3, itemGap: 20, textStyle: { color: "#50647a", fontSize: 10 } },
    tooltip: {
      trigger: "axis", axisPointer: { type: "line", lineStyle: { color: "#8b5cf6", width: 1 } },
      backgroundColor: "rgba(255,255,255,.97)", borderColor: "#dce5ed", borderWidth: 1, padding: 13,
      textStyle: { color: "#102a43", fontSize: 11 }, extraCssText: "border-radius:14px;box-shadow:0 18px 45px rgba(16,42,67,.15)",
      formatter: (raw: unknown) => {
        const items = raw as { axisValue: string; marker: string; seriesName: string; value: number }[];
        return `<strong>${new Date(`${items[0]?.axisValue}-01T00:00:00`).toLocaleDateString("en", { month: "long", year: "numeric" })}</strong><br/>${items.map((item) => `${item.marker}${item.seriesName}<b style="float:right;margin-left:28px">${Number(item.value).toLocaleString()}</b>`).join("<br/>")}<br/><small style="color:#71869a">Raw telemetry events · log scale</small>`;
      },
    },
    xAxis: { type: "category", boundaryGap: false, data: points.map((point) => point.month), axisLine: { lineStyle: { color: "#dce5ed" } }, axisTick: { show: false }, axisLabel: { color: "#71869a", fontSize: 10, formatter: (value: string) => value.replace("-", " · ") } },
    yAxis: { type: "log", name: "EVENTS / MONTH · LOG SCALE", nameTextStyle: { color: "#8799aa", fontSize: 9, padding: [0, 0, 8, 0] }, axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: "#71869a", fontSize: 9, formatter: (value: number) => value >= 1_000_000 ? `${value / 1_000_000}M` : value >= 1_000 ? `${value / 1_000}K` : `${value}` }, splitLine: { lineStyle: { color: "#e8eef3", type: "dashed" } } },
    series: SERIES.map((series, index) => ({
      name: series.name, type: "line", smooth: 0.35, symbol: "circle", showSymbol: false, symbolSize: 7,
      data: points.map((point) => point[series.key]), lineStyle: { color: series.color, width: index < 2 ? 2.5 : 2 },
      itemStyle: { color: series.color, borderColor: "#fff", borderWidth: 2 }, emphasis: { focus: "series", scale: 1.3 },
      areaStyle: { opacity: index === 0 ? 0.14 : 0.07, color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: series.color }, { offset: 1, color: "rgba(255,255,255,0)" }]) },
    })),
  }), [points]);

  useEffect(() => {
    if (!host.current || !activity.points.length) return;
    const chart = echarts.init(host.current, undefined, { renderer: "canvas" });
    chart.setOption(option());
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(host.current);
    return () => { observer.disconnect(); chart.dispose(); };
  }, [activity.points.length, option]);

  if (!activity.points.length) return <div className="grid h-[360px] place-items-center text-[11px] text-[var(--text-muted)]">{activity.provenance.reason ?? "Monthly CERT telemetry is unavailable."}</div>;
  return <div>
    <div className="mb-1 flex flex-wrap items-center justify-between gap-3">
      <p className="text-[10px] text-[var(--text-muted)]">{activity.reportingPeriod.start} — {activity.reportingPeriod.end} · {activity.reportingPeriod.months} months · exact source row counts</p>
      <div className="flex rounded-lg border border-border bg-white/70 p-0.5">{([6, 12, "all"] as const).map((value) => <button key={value} onClick={() => setRange(value)} className={`rounded-md px-2.5 py-1 text-[9px] font-semibold transition-all ${range === value ? "bg-[var(--foreground)] text-white shadow-sm" : "text-[var(--text-muted)] hover:text-foreground"}`}>{value === "all" ? "17M" : `${value}M`}</button>)}</div>
    </div>
    <div ref={host} className="h-[360px] w-full" role="img" aria-label="Monthly raw CERT logon, file, removable-media, and email telemetry. Select legend items to compare categories." />
  </div>;
}

type Stage = { id: string; label: string; count: number; tone: string; note: string };

export function IncidentLifecycleExplorer({ incidents }: { incidents: IncidentList }) {
  const [expanded, setExpanded] = useState(false);
  const missed = Math.max(0, incidents.summary.total - incidents.summary.detected);
  const stages: Stage[] = [
    { id: "created", label: "Created", count: incidents.summary.total, tone: "#2563eb", note: "Persisted controlled incidents" },
    { id: "detected", label: "Detected", count: incidents.summary.detected, tone: "#dc5a62", note: "Finding created by frozen detection policy" },
    { id: "investigation", label: "Investigated", count: incidents.items.filter((item) => item.history.some((entry) => entry.stage === "DETECT")).length, tone: "#0891b2", note: "Recorded detection history available" },
    { id: "response", label: "Response planned", count: incidents.summary.responsePlanned, tone: "#7c3aed", note: "Persisted RESPONSE_COMPLETE status" },
  ];
  return <>
    <button type="button" onClick={() => setExpanded(true)} className="incident-explorer group relative w-full overflow-hidden rounded-[18px] border border-border bg-white/74 p-4 text-left shadow-[0_14px_36px_rgba(16,42,67,.07)] transition-all duration-500 hover:-translate-y-0.5 hover:border-[#b9a7ff] hover:shadow-[0_22px_55px_rgba(86,63,170,.16)]" aria-label="Open incident lifecycle explorer">
      <div className="flex items-center justify-between"><div><div className="tech-label">Operational incident structure</div><h3 className="mt-1 text-[13px] font-semibold">Lifecycle pulse</h3></div><Expand className="size-3.5 text-[var(--text-muted)] transition-transform group-hover:scale-110" /></div>
      <div className="mt-4 grid grid-cols-3 gap-2">
        <PulseMetric value={incidents.summary.detected} label="Detected" color="#dc5a62" />
        <PulseMetric value={missed} label="Missed" color="#8799aa" />
        <PulseMetric value={incidents.summary.responsePlanned} label="Planned" color="#7c3aed" />
      </div>
      <div className="mt-4 h-16"><LifecycleFlow stages={stages} compact /></div>
      <p className="mt-2 text-[9px] leading-4 text-[var(--text-muted)]">Hover to energize the operational flow · click to explore persisted lifecycle counts.</p>
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_70%_75%,rgba(124,58,237,.10),transparent_42%)] opacity-0 transition-opacity duration-500 group-hover:opacity-100" />
    </button>
    {expanded && <div className="fixed inset-0 z-50 grid place-items-center bg-[#102a43]/25 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label="Incident lifecycle explorer">
      <div className="w-full max-w-4xl rounded-[24px] border border-white/80 bg-white/96 p-6 shadow-[0_35px_100px_rgba(16,42,67,.28)]">
        <div className="flex items-start justify-between"><div><div className="tech-label">Focused micro-explorer</div><h2 className="mt-2 text-xl font-semibold">Persisted incident lifecycle</h2><p className="mt-1 text-[11px] text-[var(--text-muted)]">Operational status structure, not literal network topology. Counts can overlap as incidents advance.</p></div><button onClick={() => setExpanded(false)} className="grid size-9 place-items-center rounded-full border border-border hover:bg-[var(--surface-hover)]" aria-label="Close explorer"><X className="size-4" /></button></div>
        <div className="my-8 h-40"><LifecycleFlow stages={stages} /></div>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">{stages.map((stage) => <article key={stage.id} className="rounded-xl border border-border bg-[var(--surface-elevated)] p-4"><span className="block size-2 rounded-full" style={{ background: stage.tone, boxShadow: `0 0 12px ${stage.tone}` }} /><strong className="mt-3 block font-mono text-2xl">{stage.count}</strong><span className="text-[11px] font-semibold">{stage.label}</span><p className="mt-2 text-[9px] leading-4 text-[var(--text-muted)]">{stage.note}</p></article>)}</div>
        <div className="mt-5 max-h-36 overflow-auto rounded-xl border border-border"><div className="grid grid-cols-[1fr_100px_130px] border-b border-border px-4 py-2 text-[9px] font-semibold uppercase tracking-wider text-[var(--text-muted)]"><span>Incident</span><span>Detection</span><span>Response</span></div>{incidents.items.map((item) => <IncidentRow key={item.incidentId} item={item} />)}</div>
      </div>
    </div>}
  </>;
}

function PulseMetric({ value, label, color }: { value: number; label: string; color: string }) { return <div className="rounded-xl border border-border/80 bg-white/80 p-2.5"><span className="font-mono text-lg font-semibold" style={{ color }}>{value}</span><span className="block text-[8px] uppercase tracking-wider text-[var(--text-muted)]">{label}</span></div>; }

function LifecycleFlow({ stages, compact = false }: { stages: Stage[]; compact?: boolean }) {
  return <svg viewBox="0 0 760 150" className="h-full w-full overflow-visible" aria-label="Incident operational lifecycle flow">
    <defs><filter id={`glow-${compact}`}><feGaussianBlur stdDeviation="3" result="blur" /><feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge></filter></defs>
    {stages.slice(0, -1).map((stage, index) => <g key={stage.id}><path d={`M ${90 + index * 190} 74 C ${140 + index * 190} 30, ${210 + index * 190} 118, ${270 + index * 190} 74`} fill="none" stroke="#d9e2ec" strokeWidth="2" /><circle className="incident-flow-particle" r="3" fill={stages[index + 1].tone}><animateMotion dur={`${2.1 + index * .35}s`} repeatCount="indefinite" path={`M ${90 + index * 190} 74 C ${140 + index * 190} 30, ${210 + index * 190} 118, ${270 + index * 190} 74`} /></circle></g>)}
    {stages.map((stage, index) => <g key={stage.id} transform={`translate(${80 + index * 190},74)`} className="incident-flow-node"><circle r={compact ? 18 : 26} fill="white" stroke={stage.tone} strokeWidth="2" filter={`url(#glow-${compact})`} /><circle r={compact ? 5 : 7} fill={stage.tone} /><text y={compact ? -27 : -38} textAnchor="middle" fill="#50647a" fontSize={compact ? 10 : 12} fontWeight="600">{stage.label}</text><text y={compact ? 36 : 48} textAnchor="middle" fill="#102a43" fontSize={compact ? 11 : 14} fontWeight="700">{stage.count}</text></g>)}
  </svg>;
}

function IncidentRow({ item }: { item: CertIncident }) { return <div className="grid grid-cols-[1fr_100px_130px] items-center px-4 py-2.5 text-[10px] odd:bg-[var(--surface-elevated)]"><span className="font-mono">{item.incidentId}</span><span>{item.detection.findingCreated ? "Detected" : "Missed"}</span><span>{item.shield.status.replaceAll("_", " ")}</span></div>; }
