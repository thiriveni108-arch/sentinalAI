import { backendHeaders, publicDemoMode } from "@/data/backend-auth";

const backend=(process.env.SENTINEL_API_BASE_URL ?? "http://127.0.0.1:8000").replace(/\/$/,"");
type Context={params:Promise<{path:string[]}>};

async function proxy(request:Request,{params}:Context){
  const {path}=await params;
  const target=`${backend}/api/shield/${path.map(encodeURIComponent).join("/")}`;
  const body=request.method==="GET"?undefined:await request.text();
  if (request.method !== "GET" && publicDemoMode()) {
    return Response.json({error:{code:"public_demo_mutation_disabled",message:"State-changing operations are disabled in public demo mode."}},{status:403});
  }
  try{
    const response=await fetch(target,{method:request.method,headers:backendHeaders(Boolean(body)),body,cache:"no-store"});
    return new Response(await response.text(),{status:response.status,headers:{"content-type":response.headers.get("content-type")??"application/json"}});
  }catch{
    return Response.json({error:{code:"simulator_unavailable",message:"The local simulator API is unavailable. Start the backend and retry."}},{status:503});
  }
}
export const GET=proxy;
export const POST=proxy;
