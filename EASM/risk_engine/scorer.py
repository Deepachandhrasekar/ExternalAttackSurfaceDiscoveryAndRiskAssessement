def calculate_risk_score(findings):

    total = sum(f["weight"] for f in findings)

    if total >= 80:
        level = "CRITICAL"
    elif total >= 50:
        level = "HIGH"
    elif total >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "total_score": round(total, 1),
        "risk_level": level
    }