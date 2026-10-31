"use server";

import type { ContainmentState, ResponseAction, ResponseHistory } from "@/domain/sentinel";
import { backendHeaders, publicDemoMode } from "@/data/backend-auth";

export interface ContainmentActionInput {
  employeeId: string;
  alertId: string;
  action: ResponseAction;
  reason: string;
}

export interface ContainmentActionResult {
  ok: boolean;
  state?: ContainmentState;
  history?: ResponseHistory;
  error?: string;
}

const endpoints: Record<ResponseAction, string> = {
  BLOCK_USER: "block",
  UNBLOCK_USER: "unblock",
  REVOKE_SESSIONS: "revoke-sessions",
  RESTORE_SESSIONS: "restore-sessions",
  BLOCK_AND_REVOKE: "contain",
};

export async function performContainmentAction(input: ContainmentActionInput): Promise<ContainmentActionResult> {
  const reason = input.reason.trim();
  if (!reason || reason.length > 240) return { ok: false, error: "Enter a reason of 240 characters or fewer." };
  if (!(input.action in endpoints)) return { ok: false, error: "Unsupported containment action." };
  if (process.env.SENTINEL_DATA_SOURCE?.toLowerCase() !== "http") {
    return { ok: false, error: "Containment actions require the live SentinelAI API." };
  }
  if (publicDemoMode()) return { ok: false, error: "Containment actions are disabled in public demo mode." };

  const baseUrl = (process.env.SENTINEL_API_BASE_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");
  const employeeId = encodeURIComponent(input.employeeId);
  try {
    const response = await fetch(`${baseUrl}/api/response/users/${employeeId}/${endpoints[input.action]}`, {
      method: "POST",
      cache: "no-store",
      headers: backendHeaders(true),
      body: JSON.stringify({ alertId: input.alertId, reason, actor: "Analyst" }),
    });
    const document = await response.json().catch(() => ({})) as { state?: ContainmentState; error?: { message?: string } };
    if (!response.ok || !document.state) {
      return { ok: false, error: document.error?.message ?? "Containment action could not be completed." };
    }
    const historyResponse = await fetch(`${baseUrl}/api/response/users/${employeeId}/history`, { cache: "no-store", headers: backendHeaders() });
    const history = historyResponse.ok ? await historyResponse.json() as ResponseHistory : { items: [] };
    return { ok: true, state: document.state, history };
  } catch {
    return { ok: false, error: "Containment action could not be completed." };
  }
}
