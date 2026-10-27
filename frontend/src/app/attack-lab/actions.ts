"use server";

import { redirect } from "next/navigation";
import { getSentinelDataSource } from "@/data/data-source";
import { SentinelApiError } from "@/data/http-data-source";

function value(formData: FormData, key: string) { return String(formData.get(key) ?? "").trim(); }

export async function createAttackLabRun(formData: FormData) {
  const employeeId = value(formData, "employeeId");
  const scenario = value(formData, "scenario");
  const intensity = value(formData, "intensity");
  const startTime = value(formData, "startTime");
  if (!employeeId || !scenario || !startTime || !["standard", "elevated"].includes(intensity)) {
    redirect("/attack-lab?error=invalid_request");
  }
  try {
    const run = await getSentinelDataSource().createAttackLabRun({ employeeId, scenario, intensity: intensity as "standard" | "elevated", startTime: new Date(startTime).toISOString() });
    redirect(`/attack-lab/${encodeURIComponent(run.simulationId)}`);
  } catch (error) {
    if (error instanceof SentinelApiError) redirect(`/attack-lab?error=${encodeURIComponent(error.code)}`);
    throw error;
  }
}

export async function createCertIncident(formData: FormData) {
  const record = value(formData, "record");
  const [user, date] = record.split("|");
  if (!user || !date) redirect("/attack-lab?error=invalid_cert_record");
  try {
    const incident = await getSentinelDataSource().createIncident({ user, date, split: "test", scenario: "suspicious-file-collection" });
    redirect(`/investigation?incident=${encodeURIComponent(incident.incidentId)}`);
  } catch (error) {
    if (error instanceof SentinelApiError) redirect(`/attack-lab?error=${encodeURIComponent(error.code)}`);
    throw error;
  }
}

export async function planIncidentShield(formData: FormData) {
  const incidentId = value(formData, "incidentId");
  if (!incidentId) redirect("/shield?error=incident_required");
  try {
    await getSentinelDataSource().planIncidentResponse(incidentId);
    redirect(`/shield?incident=${encodeURIComponent(incidentId)}`);
  } catch (error) {
    if (error instanceof SentinelApiError) redirect(`/shield?incident=${encodeURIComponent(incidentId)}&error=${encodeURIComponent(error.code)}`);
    throw error;
  }
}
