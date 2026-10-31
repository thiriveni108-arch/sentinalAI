import { backendHeaders } from "@/data/backend-auth";

const backend=(process.env.SENTINEL_API_BASE_URL ?? "http://127.0.0.1:8000").replace(/\/$/,"");
type Context={params:Promise<{incidentId:string}>};
export async function GET(_:Request,{params}:Context){
  const {incidentId}=await params;
  try{const response=await fetch(`${backend}/api/incidents/${encodeURIComponent(incidentId)}/quantum-diagnostics`,{cache:"no-store",headers:backendHeaders()});return new Response(await response.text(),{status:response.status,headers:{"content-type":"application/json"}})}
  catch{return Response.json({error:{code:"diagnostics_unavailable",message:"The local research API is unavailable."}},{status:503})}
}
