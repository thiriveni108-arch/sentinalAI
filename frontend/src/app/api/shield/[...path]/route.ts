const backend = (process.env.SENTINEL_API_BASE_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");
const apiKey = process.env.SENTINEL_API_KEY;
type Context = { params: Promise<{ path: string[] }> };

async function proxy(request: Request, { params }: Context) {
  const { path } = await params;
  const target = `${backend}/api/shield/${path.map(encodeURIComponent).join("/")}`;
  const body = request.method === "GET" ? undefined : await request.text();
  const headers: Record<string, string> = { accept: "application/json" };
  if (body) headers["content-type"] = "application/json";
  if (apiKey) headers["x-sentinel-api-key"] = apiKey;
  try {
    const response = await fetch(target, { method: request.method, headers, body, cache: "no-store" });
    return new Response(await response.text(), {
      status: response.status,
      headers: { "content-type": response.headers.get("content-type") ?? "application/json" },
    });
  } catch {
    return Response.json(
      { error: { code: "simulator_unavailable", message: "The local simulator API is unavailable. Start the backend and retry." } },
      { status: 503 },
    );
  }
}
export const GET = proxy;
export const POST = proxy;
