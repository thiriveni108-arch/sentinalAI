import type { RiskLevel } from "@/domain/sentinel";

export const severityClass: Record<RiskLevel, string> = {
  Low: "text-[var(--low)] border-[color:var(--low)]/35 bg-[color:var(--low)]/8",
  Medium: "text-[var(--medium)] border-[color:var(--medium)]/35 bg-[color:var(--medium)]/8",
  High: "text-[var(--high)] border-[color:var(--high)]/35 bg-[color:var(--high)]/8",
  Critical: "text-[var(--critical)] border-[color:var(--critical)]/35 bg-[color:var(--critical)]/8",
};

export const severityTextClass: Record<RiskLevel, string> = {
  Low: "text-[var(--low)]", Medium: "text-[var(--medium)]", High: "text-[var(--high)]", Critical: "text-[var(--critical)]",
};

const threatTimestamp = new Intl.DateTimeFormat("en-GB", {day:"2-digit",month:"short",hour:"2-digit",minute:"2-digit",hour12:false,timeZone:"Asia/Kolkata"});
export function formatThreatTimestamp(value:string){const formatted=threatTimestamp.format(new Date(value));const [date,time]=formatted.split(", ");return{date,time,full:`${date}, ${time} IST`}}

const labels: Record<string, string> = {
  POST_ACTION_MALICIOUS_ACTIVITY: "Suspicious activity observed",
  POST_ACTION_NO_CONFIRMED_ACTIVITY: "No confirmed suspicious activity",
  REVOKE_SESSION: "Revoke active session",
  REQUIRE_FRESH_MFA: "Require fresh authentication",
  DISABLE_BULK_EXPORT: "Restrict bulk data export",
  ROLLBACK: "Restore affected workflow",
  PENDING_HUMAN: "Waiting for authorized approval",
  PENDING_ANALYST: "Waiting for analyst approval",
  AUTO_AUTHORIZED: "Authorized by narrow safety policy",
  AUTHORIZED: "Authorized for simulated execution",
  RECOVERY_PENDING: "Recovery review required",
  target_cumulative_exposure: "Expected exposure",
  target_severe_outcome: "Severe-outcome probability",
  target_cumulative_disruption: "Expected business disruption",
};

export function humanLabel(value: string): string {
  return labels[value] ?? value.replaceAll("_", " ").replaceAll("-", " ").toLowerCase().replace(/\b\w/g, letter => letter.toUpperCase());
}

export function shortId(value: string): string { return value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-5)}` : value; }
