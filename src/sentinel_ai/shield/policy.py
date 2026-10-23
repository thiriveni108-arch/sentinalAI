def recommendation(risk_score: float, evidence_count: int, criticality: int, reversible: bool, feasible: bool) -> dict:
    if not feasible:
        level = "URGENT_ANALYST_ESCALATION"
    elif risk_score >= 85 and criticality >= 4 and evidence_count >= 2:
        level = "TARGETED_CONTAINMENT"
    elif risk_score >= 60:
        level = "STEP_UP_AUTHENTICATION_AND_INVESTIGATE"
    else:
        level = "MONITOR_AND_INVESTIGATE"
    return {
        "decision": level,
        "approvalRequired": level in {"TARGETED_CONTAINMENT", "URGENT_ANALYST_ESCALATION"} or not reversible,
        "reasons": [f"Risk score {risk_score:.0f}/100 is a bounded risk score, not compromise probability.",
                    f"{evidence_count} modeled evidence signals support the scenario.",
                    f"Maximum path criticality is {criticality}/5."],
        "quantumConfidenceUsed": False,
    }
