"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import type { ShieldPlan, UnifiedShieldSession } from "@/domain/unified-incident";

async function request<T>(path:string,body?:object):Promise<T>{
  const response=await fetch(path,{method:body?"POST":"GET",headers:body?{"content-type":"application/json"}:undefined,body:body?JSON.stringify(body):undefined,cache:"no-store"});
  const data=await response.json().catch(()=>({}));
  if(!response.ok) throw new Error(data?.error?.message ?? data?.detail?.message ?? "The simulator service could not complete this request.");
  return data as T;
}

interface IncidentContextValue {
  session: UnifiedShieldSession|null; plan: ShieldPlan|null; loading:boolean; error:string;
  create(topology:string):Promise<void>; refresh():Promise<void>; select(id:string|null):void;
  planResponse():Promise<void>; submit():Promise<void>; decide(identity:string,decision:"approve"|"reject"):Promise<void>;
  execute():Promise<void>; recover(identity:string):Promise<void>;
}
const IncidentContext=createContext<IncidentContextValue|null>(null);

export function IncidentProvider({children}:{children:React.ReactNode}){
  const search=useSearchParams(); const pathname=usePathname(); const router=useRouter(); const selected=search.get("session");
  const [session,setSession]=useState<UnifiedShieldSession|null>(null); const [plan,setPlan]=useState<ShieldPlan|null>(null); const [loading,setLoading]=useState(false); const [error,setError]=useState("");
  const select=useCallback((id:string|null)=>{const query=new URLSearchParams(search.toString()); if(id)query.set("session",id);else query.delete("session"); router.replace(`${pathname}${query.size?`?${query}`:""}`);},[pathname,router,search]);
  const refresh=useCallback(async()=>{if(!selected){setSession(null);setPlan(null);return} setLoading(true);setError("");try{const next=await request<UnifiedShieldSession>(`/api/shield/sessions/${encodeURIComponent(selected)}`);setSession(current=>{if(!current||current.incident_id!==next.incident_id||current.version!==next.version)setPlan(null);return next})}catch(e){setSession(null);setPlan(null);setError(e instanceof Error?e.message:"Session unavailable after restart.")}finally{setLoading(false)}},[selected]);
  useEffect(()=>{const frame=requestAnimationFrame(()=>void refresh());return()=>cancelAnimationFrame(frame)},[refresh]);
  const mutate=useCallback(async(path:string,body:object)=>{if(!session)return;setLoading(true);setError("");try{const next=await request<UnifiedShieldSession>(path,body);if(next.version!==session.version)setPlan(null);setSession(next)}catch(e){setPlan(null);setError(e instanceof Error?e.message:"Request failed");await refresh()}finally{setLoading(false)}},[refresh,session]);
  const value=useMemo<IncidentContextValue>(()=>({session,plan,loading,error,select,refresh,
    create:async(topology)=>{setLoading(true);setError("");setPlan(null);try{const next=await request<UnifiedShieldSession>("/api/shield/sessions",{scenario:"credential-compromise",topology,seed:96001});setSession(next);select(next.incident_id)}catch(e){setError(e instanceof Error?e.message:"Unable to create session")}finally{setLoading(false)}},
    planResponse:async()=>{if(!session)return;setLoading(true);setError("");try{const next=await request<ShieldPlan>(`/api/shield/sessions/${session.incident_id}/plan`,{version:session.version});if(next.version!==session.version)throw new Error("The incident changed while planning. Refresh before comparing responses.");setPlan(next)}catch(e){setPlan(null);setError(e instanceof Error?e.message:"Planning failed")}finally{setLoading(false)}},
    submit:()=>mutate(`/api/shield/sessions/${session?.incident_id}/submit`,{version:session?.version}),
    decide:(identity,decision)=>mutate(`/api/shield/sessions/${session?.incident_id}/approval`,{version:session?.version,identity,decision}),
    execute:()=>mutate(`/api/shield/sessions/${session?.incident_id}/execute`,{version:session?.version}),
    recover:(identity)=>mutate(`/api/shield/sessions/${session?.incident_id}/recovery`,{version:session?.version,identity}),
  }),[error,loading,mutate,plan,refresh,select,session]);
  return <IncidentContext.Provider value={value}>{children}</IncidentContext.Provider>;
}
export function useIncident(){const value=useContext(IncidentContext);if(!value)throw new Error("useIncident must be used inside IncidentProvider");return value}
