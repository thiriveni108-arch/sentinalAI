"use client";

import { useEffect, useRef } from "react";
import * as echarts from "echarts/core";
import { BarChart, PieChart, RadarChart } from "echarts/charts";
import { GridComponent, LegendComponent, RadarComponent, TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import type { EChartsCoreOption } from "echarts/core";

echarts.use([BarChart, PieChart, RadarChart, GridComponent, LegendComponent, RadarComponent, TooltipComponent, CanvasRenderer]);

type ModelPoint = { name: string; before: number; after: number; threshold: number; prediction: number };
type FeaturePoint = { feature: string; before: number; after: number; delta: number };

function palette() {
  const style = getComputedStyle(document.documentElement);
  const read = (name: string) => style.getPropertyValue(name).trim();
  return { accent: read("--accent"), quantum: read("--quantum"), high: read("--high"), critical: read("--critical"), low: read("--low"), border: read("--border"), muted: read("--text-muted"), text: read("--foreground"), surface: read("--surface") };
}

function IntelligenceChart({ option, label, height = 270 }: { option: (colors: ReturnType<typeof palette>) => EChartsCoreOption; label: string; height?: number }) {
  const host = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!host.current) return;
    const chart = echarts.init(host.current, undefined, { renderer: "canvas" });
    chart.setOption(option(palette()));
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(host.current);
    return () => { observer.disconnect(); chart.dispose(); };
  }, [option]);
  return <div ref={host} role="img" aria-label={label} style={{ height }} className="w-full" />;
}

const axis = (c: ReturnType<typeof palette>) => ({ axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: c.muted, fontSize: 9 }, splitLine: { lineStyle: { color: c.border, type: "dashed" } } });
const tooltip = (c: ReturnType<typeof palette>) => ({ trigger: "axis" as const, backgroundColor: `${c.surface}f2`, borderColor: c.border, borderWidth: 1, textStyle: { color: c.text, fontSize: 10 }, extraCssText: "border-radius:12px;box-shadow:0 14px 35px rgba(16,42,67,.14);backdrop-filter:blur(12px)" });

export function IncidentBreakdownChart({ total, detected, responsePlanned }: { total: number; detected: number; responsePlanned: number }) {
  const missed = Math.max(0, total - detected);
  const option = (c: ReturnType<typeof palette>): EChartsCoreOption => ({ animationDuration: 700, tooltip: { ...tooltip(c), trigger: "item" }, legend: { bottom: 0, icon: "circle", textStyle: { color: c.muted, fontSize: 9 } }, series: [{ type: "pie", radius: ["55%", "76%"], center: ["50%", "43%"], padAngle: 3, itemStyle: { borderRadius: 7, borderColor: c.surface, borderWidth: 3 }, label: { show: true, position: "center", formatter: `{value|${total}}\n{name|INCIDENTS}`, rich: { value: { color: c.text, fontSize: 27, fontWeight: 700, lineHeight: 34 }, name: { color: c.muted, fontSize: 9, letterSpacing: 2 } } }, data: [{ name: "Detected", value: detected, itemStyle: { color: c.high }, label: { show: true } }, { name: "Missed", value: missed, itemStyle: { color: c.muted }, label: { show: false } }, { name: "Response planned", value: responsePlanned, itemStyle: { color: c.quantum }, label: { show: false } }] }] });
  return <IntelligenceChart option={option} label="Persisted connected incident breakdown" height={245} />;
}

export function ModelDecisionChart({ models }: { models: ModelPoint[] }) {
  const option = (c: ReturnType<typeof palette>): EChartsCoreOption => ({ animationDuration: 650, tooltip: { ...tooltip(c), formatter: (items: unknown) => { const values = items as { seriesName: string; value: number; axisValue: string; marker: string }[]; return `<strong>${values[0]?.axisValue}</strong><br/>${values.map(item => `${item.marker}${item.seriesName}: ${Number(item.value).toFixed(4)}`).join("<br/>")}<br/><small>Raw decision values, not probabilities</small>`; } }, legend: { top: 0, right: 0, textStyle: { color: c.muted, fontSize: 9 } }, grid: { left: 45, right: 15, top: 42, bottom: 35 }, xAxis: { type: "category", data: models.map(item => item.name), ...axis(c) }, yAxis: { type: "value", ...axis(c) }, series: [{ name: "Before", type: "bar", data: models.map(item => item.before), barMaxWidth: 24, itemStyle: { color: c.border, borderRadius: [6, 6, 0, 0] } }, { name: "Injected", type: "bar", data: models.map(item => ({ value: item.after, itemStyle: { color: item.prediction ? c.high : c.low, borderRadius: [6, 6, 0, 0] } })), barMaxWidth: 24 }, { name: "Decision threshold", type: "bar", data: models.map(item => item.threshold), barMaxWidth: 5, itemStyle: { color: c.quantum, borderRadius: 4 } }] });
  return <IntelligenceChart option={option} label="Before and injected raw detector decision scores with thresholds" />;
}

export function FeatureDeltaChart({ changes }: { changes: FeaturePoint[] }) {
  const shown = [...changes].sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta)).slice(0, 8);
  const option = (c: ReturnType<typeof palette>): EChartsCoreOption => ({ animationDuration: 700, tooltip: { ...tooltip(c), formatter: (items: unknown) => { const item = (items as { dataIndex: number; value: number }[])[0]; const row = shown[item.dataIndex]; return `<strong>${row.feature.replaceAll("_", " ")}</strong><br/>Before: ${row.before}<br/>After: ${row.after}<br/>Observed delta: ${row.delta >= 0 ? "+" : ""}${row.delta}`; } }, grid: { left: 138, right: 24, top: 16, bottom: 24 }, xAxis: { type: "value", ...axis(c) }, yAxis: { type: "category", inverse: true, data: shown.map(item => item.feature.replaceAll("_", " ")), ...axis(c), axisLabel: { color: c.muted, fontSize: 9, width: 125, overflow: "truncate" } }, series: [{ type: "bar", data: shown.map(item => ({ value: item.delta, itemStyle: { color: item.delta >= 0 ? c.quantum : c.low, borderRadius: item.delta >= 0 ? [0, 6, 6, 0] : [6, 0, 0, 6] } })), barMaxWidth: 18, label: { show: true, position: "right", color: c.muted, fontSize: 9, formatter: ({ value }: { value: number }) => `${value >= 0 ? "+" : ""}${value}` } }] });
  return <IntelligenceChart option={option} label="Largest persisted feature changes in the controlled exercise" height={290} />;
}

export function BenchmarkRadarChart({ models }: { models: { name: string; precision?: number; recall?: number; f1?: number; balancedAccuracy?: number }[] }) {
  const option = (c: ReturnType<typeof palette>): EChartsCoreOption => ({ animationDuration: 800, tooltip: { ...tooltip(c), trigger: "item" }, legend: { bottom: 0, icon: "circle", textStyle: { color: c.muted, fontSize: 9 } }, radar: { radius: "62%", center: ["50%", "46%"], splitNumber: 4, indicator: [{ name: "Precision", max: 1 }, { name: "Recall", max: 1 }, { name: "F1", max: 1 }, { name: "Balanced accuracy", max: 1 }], axisName: { color: c.muted, fontSize: 9 }, splitLine: { lineStyle: { color: c.border } }, splitArea: { areaStyle: { color: ["transparent", `${c.quantum}08`] } }, axisLine: { lineStyle: { color: c.border } } }, series: [{ type: "radar", symbolSize: 5, data: models.map((model, index) => ({ name: model.name, value: [model.precision ?? 0, model.recall ?? 0, model.f1 ?? 0, model.balancedAccuracy ?? 0], lineStyle: { width: 2 }, areaStyle: { opacity: .07 }, itemStyle: { color: [c.quantum, c.accent, c.high, c.low][index % 4] } })) }] });
  return <IntelligenceChart option={option} label="Persisted benchmark metric comparison" height={330} />;
}

export function ConsequenceComparisonChart({ alternatives }: { alternatives: { action: string; exposure: number; severe: number; disruption: number }[] }) {
  const shown = alternatives.slice(0, 6);
  const option = (c: ReturnType<typeof palette>): EChartsCoreOption => ({ animationDuration: 700, tooltip: { ...tooltip(c), formatter: (items: unknown) => { const values=items as {axisValue:string;marker:string;seriesName:string;value:number}[]; return `<strong>${values[0]?.axisValue.replaceAll("_"," ")}</strong><br/>${values.map(item=>`${item.marker}${item.seriesName}: ${Number(item.value).toFixed(3)}`).join("<br/>")}<br/><small>Predicted model units; not observed outcomes</small>`; } }, legend: { top: 0, right: 0, textStyle: { color: c.muted, fontSize: 9 } }, grid: { left: 45, right: 18, top: 42, bottom: 65 }, xAxis: { type: "category", data: shown.map(item => item.action.replaceAll("_", " ")), ...axis(c), axisLabel: { color: c.muted, fontSize: 8, rotate: 18, width: 90, overflow: "truncate" } }, yAxis: { type: "value", ...axis(c) }, series: [{ name: "Exposure", type: "bar", stack: "consequence", data: shown.map(item => item.exposure), itemStyle: { color: c.high, borderRadius: [4,4,0,0] } }, { name: "Severe outcome", type: "bar", stack: "consequence", data: shown.map(item => item.severe), itemStyle: { color: c.critical } }, { name: "Disruption", type: "bar", data: shown.map(item => item.disruption), itemStyle: { color: c.quantum, borderRadius: [5,5,0,0] } }] });
  return <IntelligenceChart option={option} label="Predicted consequence comparison across feasible response actions" height={290} />;
}
