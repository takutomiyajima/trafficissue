"""Simple confirmation-priority scoring for static findings."""

WEIGHTS = {
    "permission": 1,
    "sensitive_api_hint": 2,
    "network_api_hint": 1,
    "sdk_hint": 2,
    "domain": 2,
    "url": 2,
    "network_security": 1,
}


def score_findings(findings):
    score = sum(WEIGHTS.get(item.get("signal_type", ""), 0) for item in findings)
    if score >= 9:
        label = "重要確認"
    elif score >= 6:
        label = "優先確認"
    elif score >= 3:
        label = "確認推奨"
    else:
        label = "情報"
    return {"score": score, "priority": label}
