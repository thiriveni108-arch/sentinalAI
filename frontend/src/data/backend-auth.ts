import "server-only";

export function backendHeaders(json = false): Record<string, string> {
  const headers: Record<string, string> = { accept: "application/json" };
  if (json) headers["content-type"] = "application/json";
  const secret = process.env.SENTINEL_DEMO_API_SECRET;
  if (secret) headers.authorization = `Bearer ${secret}`;
  return headers;
}

export function publicDemoMode(): boolean {
  return ["1", "true", "yes", "on"].includes((process.env.SENTINEL_PUBLIC_DEMO_MODE ?? "").toLowerCase());
}
