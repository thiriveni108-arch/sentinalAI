"""Reproducible live-API proof of CERT -> SHIELD -> Phase 8 -> Phase 10.

Run the API on 127.0.0.1:8000, then execute this script from the repository root.
It never substitutes a standalone session or assumes detector success.
"""
from __future__ import annotations

import json
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

BASE="http://127.0.0.1:8000"

def call(method,path,body=None):
    request=Request(BASE+path,data=json.dumps(body).encode() if body is not None else None,
        headers={"content-type":"application/json","accept":"application/json"},method=method)
    try:
        with urlopen(request,timeout=120) as response: return json.load(response)
    except HTTPError as error:
        raise RuntimeError(f"{method} {path} failed ({error.code}): {error.read().decode()}") from error

def main():
    findings=call("GET","/api/cert/findings?prediction=0&page_size=1")["items"]
    if not findings: raise RuntimeError("No genuine CERT employee-day is available")
    source=findings[0]
    incident=call("POST","/api/incidents",{"user":source["user"],"date":source["date"],"split":"test","scenario":"suspicious-file-collection"})
    iid=incident["incidentId"]
    session=call("POST",f"/api/incidents/{iid}/shield/session",{"topology":"small-office","seed":96001})
    plan=call("POST",f"/api/shield/sessions/{iid}/plan",{"version":session["version"]})
    session=call("POST",f"/api/shield/sessions/{iid}/submit",{"version":session["version"]})
    if session["lifecycle_status"] in {"PENDING_ANALYST","PENDING_HUMAN"}:
        identity="simulated-analyst" if session["lifecycle_status"]=="PENDING_ANALYST" else "simulated-human"
        session=call("POST",f"/api/shield/sessions/{iid}/approval",{"version":session["version"],"identity":identity,"decision":"approve"})
    session=call("POST",f"/api/shield/sessions/{iid}/execute",{"version":session["version"]})
    if session["lifecycle_status"]=="RECOVERY_PENDING":
        session=call("POST",f"/api/shield/sessions/{iid}/recovery",{"version":session["version"],"identity":"simulated-analyst"})
    final_incident=call("GET",f"/api/incidents/{iid}")
    fingerprint=session["experience_ingestion"].get("fingerprint")
    experiences=call("GET","/api/shield/learning/experiences")["items"]
    report={"version":"sentinel-e2e-evidence-report-v1","certIncidentId":iid,
        "employee":{"user":incident["canonicalRecord"]["user"],"date":incident["canonicalRecord"]["date"]},
        "detection":{"outcome":incident["detection"]["outcome"],"models":incident["detection"]["injected"]["models"],
            "initiatedBy":incident["linkage"]["initiatedBy"]},
        "shield":{"sessionId":session["session_id"],"mode":session["mode"],"topology":session["topology"],
            "hypothetical":True,"adapter":session["adapter"],"belief":session["belief"]},
        "planning":{"solver":plan["plan"]["solver"],"action":plan["plan"]["action"],"uncertainty":plan["uncertainty"]},
        "phase8":{"proposalId":session["proposal"]["proposal_id"],"status":session["lifecycle_status"],
            "verification":session["proposal"].get("feedback",{}).get("verification")},
        "phase10":{"fingerprint":fingerprint,"stored":any(x["fingerprint"]==fingerprint for x in experiences),
            "eligible":session["experience_ingestion"]["eligible"],"reasons":session["experience_ingestion"]["reasons"]},
        "canonicalLinkage":final_incident["linkage"]}
    print(json.dumps(report,indent=2))
    return 0

if __name__=="__main__":
    try: sys.exit(main())
    except Exception as error:
        print(json.dumps({"version":"sentinel-e2e-evidence-report-v1","status":"FAILED","error":str(error)},indent=2),file=sys.stderr)
        sys.exit(1)
