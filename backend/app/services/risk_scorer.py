"""Risk Scoring Engine - Calculates 0-100 risk score with explainable factors."""


def calculate_risk_score(iocs: list[dict], enrichment: dict) -> tuple[int, str, list[dict]]:
    """
    Calculate risk score based on enrichment data.
    Returns (score, level, factors).
    """
    score = 0
    factors = []

    # CVE-based scoring
    for cve in enrichment.get("cves", []):
        cvss = cve.get("cvss", 0)
        if cvss > 9:
            factor_score = 30
            factors.append({"factor": f"CVSS > 9 ({cve['id']}: {cvss})", "score": factor_score})
        elif cvss >= 7:
            factor_score = 20
            factors.append({"factor": f"CVSS 7-9 ({cve['id']}: {cvss})", "score": factor_score})
        elif cvss >= 4:
            factor_score = 10
            factors.append({"factor": f"CVSS 4-7 ({cve['id']}: {cvss})", "score": factor_score})
        else:
            factor_score = 5
            factors.append({"factor": f"CVSS < 4 ({cve['id']}: {cvss})", "score": factor_score})
        score += factor_score

        # Exploit availability
        if cve.get("exploit_available"):
            factors.append({"factor": "Public exploit available", "score": 25})
            score += 25

        # Malware association
        malware_families = cve.get("malware_families", [])
        if malware_families:
            family_str = ", ".join(malware_families[:3])
            factors.append({"factor": f"Malware associated ({family_str})", "score": 15})
            score += 15

        # Threat actor
        threat_actors = cve.get("threat_actors", [])
        if threat_actors:
            actor_str = ", ".join(threat_actors[:3])
            factors.append({"factor": f"Known threat actor ({actor_str})", "score": 10})
            score += 10

    # IOC reputation scoring
    malicious_count = sum(1 for ioc in iocs if ioc.get("reputation") == "malicious")
    suspicious_count = sum(1 for ioc in iocs if ioc.get("reputation") == "suspicious")

    if malicious_count > 0:
        rep_score = min(20, malicious_count * 10)
        factors.append({"factor": f"High IOC reputation ({malicious_count} malicious)", "score": rep_score})
        score += rep_score
    elif suspicious_count > 0:
        rep_score = min(10, suspicious_count * 5)
        factors.append({"factor": f"Suspicious IOCs ({suspicious_count} found)", "score": rep_score})
        score += rep_score

    # If no CVEs but has IOCs, give a base score
    if not enrichment.get("cves") and iocs:
        ioc_count = len(iocs)
        base_score = min(20, ioc_count * 5)
        factors.append({"factor": f"IOCs detected ({ioc_count} indicators)", "score": base_score})
        score += base_score

    # Cap at 100
    score = min(100, score)

    # Determine risk level
    if score >= 81:
        level = "critical"
    elif score >= 61:
        level = "high"
    elif score >= 31:
        level = "medium"
    else:
        level = "low"

    return score, level, factors
