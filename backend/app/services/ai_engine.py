"""AI Engine - Google Gemini integration for threat analysis and report generation."""

import os
import json
import logging
import hashlib
from typing import Optional

import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

# Simple in-memory cache for AI responses
_response_cache: dict[str, dict] = {}

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")


def _get_model():
    """Get configured Gemini model."""
    if not GEMINI_API_KEY:
        return None
    genai.configure(api_key=GEMINI_API_KEY)
    return genai.GenerativeModel("gemini-1.5-flash")


def _cache_key(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


def generate_threat_report(text: str, iocs: list[dict], enrichment: dict, mitre_mappings: list[dict]) -> Optional[dict]:
    """Generate AI threat intelligence report using Gemini."""
    cache_k = _cache_key(f"report:{text}")
    if cache_k in _response_cache:
        logger.info("Returning cached AI report")
        return _response_cache[cache_k]

    model = _get_model()
    if not model:
        logger.warning("No Gemini API key configured, using fallback report")
        return _generate_fallback_report(text, iocs, enrichment, mitre_mappings)

    ioc_summary = ", ".join([f"{i['type']}:{i['value']}" for i in iocs[:10]])
    cve_summary = ", ".join([f"{c['id']} (CVSS:{c['cvss']})" for c in enrichment.get("cves", [])])
    mitre_summary = ", ".join([f"{m['tactic']}/{m['technique']} ({m['id']})" for m in mitre_mappings[:10]])

    prompt = f"""You are a senior cybersecurity threat analyst. Analyze the following threat intelligence and produce a structured report.

THREAT DATA:
{text}

EXTRACTED IOCs: {ioc_summary}
CVE DETAILS: {cve_summary if cve_summary else "None identified"}
MITRE ATT&CK MAPPING: {mitre_summary if mitre_summary else "Pending analysis"}

Generate a JSON response with EXACTLY this structure (no markdown, no code blocks, just pure JSON):
{{
    "summary": "2-3 sentence executive threat summary",
    "attack_scenario": "Detailed paragraph explaining how an attacker would exploit this threat",
    "business_impact": "What happens if this threat succeeds - financial, operational, reputational impact",
    "immediate_actions": ["action1", "action2", "action3", "action4"],
    "long_term_remediation": ["strategy1", "strategy2", "strategy3", "strategy4"],
    "monitoring": ["recommendation1", "recommendation2", "recommendation3", "recommendation4"]
}}

Be specific to the actual IOCs and CVEs found. Do not be generic."""

    try:
        response = model.generate_content(prompt)
        response_text = response.text.strip()

        # Clean up response - remove markdown code blocks if present
        if response_text.startswith("```"):
            lines = response_text.split("\n")
            lines = [l for l in lines if not l.startswith("```")]
            response_text = "\n".join(lines)

        report = json.loads(response_text)
        _response_cache[cache_k] = report
        return report
    except Exception as e:
        logger.error(f"AI report generation failed: {e}")
        return _generate_fallback_report(text, iocs, enrichment, mitre_mappings)


def generate_mitre_mappings(text: str, iocs: list[dict]) -> Optional[list[dict]]:
    """Use AI to identify MITRE ATT&CK techniques from threat data."""
    cache_k = _cache_key(f"mitre:{text}")
    if cache_k in _response_cache:
        logger.info("Returning cached MITRE mappings")
        return _response_cache[cache_k]

    model = _get_model()
    if not model:
        return None

    ioc_summary = ", ".join([f"{i['type']}:{i['value']}" for i in iocs[:10]])

    prompt = f"""You are a MITRE ATT&CK expert. Analyze this threat data and identify the most relevant ATT&CK techniques.

THREAT DATA:
{text}

EXTRACTED IOCs: {ioc_summary}

Return a JSON array with 3-6 relevant techniques. Use EXACTLY this format (no markdown, no code blocks, just pure JSON array):
[
    {{"tactic": "Tactic Name", "technique": "Technique Name", "id": "T####", "confidence": "high/medium/low"}},
    ...
]

Only include techniques that are clearly relevant to the threat data. Common tactics include:
- Initial Access (T1566, T1190, T1189)
- Execution (T1059, T1059.001)
- Persistence (T1547.001)
- Privilege Escalation (T1068)
- Credential Access (T1003, T1566.002)
- Lateral Movement (T1021)
- Exfiltration (T1041)
- Impact (T1486)
- Command and Control (T1071)"""

    try:
        response = model.generate_content(prompt)
        response_text = response.text.strip()

        if response_text.startswith("```"):
            lines = response_text.split("\n")
            lines = [l for l in lines if not l.startswith("```")]
            response_text = "\n".join(lines)

        mappings = json.loads(response_text)
        _response_cache[cache_k] = mappings
        return mappings
    except Exception as e:
        logger.error(f"AI MITRE mapping failed: {e}")
        return None


def _generate_fallback_report(text: str, iocs: list[dict], enrichment: dict, mitre_mappings: list[dict]) -> dict:
    """Generate a rule-based fallback report when AI is unavailable."""
    ioc_types = [i["type"] for i in iocs]
    cves = enrichment.get("cves", [])

    # Build summary
    threat_elements = []
    if "domain" in ioc_types:
        domains = [i["value"] for i in iocs if i["type"] == "domain"]
        threat_elements.append(f"malicious domain(s): {', '.join(domains[:3])}")
    if "ipv4" in ioc_types:
        ips = [i["value"] for i in iocs if i["type"] == "ipv4"]
        threat_elements.append(f"suspicious IP(s): {', '.join(ips[:3])}")
    if cves:
        cve_str = ", ".join([f"{c['id']} (CVSS {c['cvss']})" for c in cves[:3]])
        threat_elements.append(f"vulnerability: {cve_str}")

    summary = f"Threat analysis identified {len(iocs)} indicators of compromise"
    if threat_elements:
        summary += f" including {'; '.join(threat_elements)}."
    else:
        summary += "."
    if cves and cves[0].get("cvss", 0) >= 9:
        summary += " Critical severity - immediate action required."

    # Build actions based on IOCs found
    immediate_actions = []
    if any(i["type"] == "domain" for i in iocs):
        for d in [i["value"] for i in iocs if i["type"] == "domain"][:2]:
            immediate_actions.append(f"Block domain {d} at DNS/proxy level")
    if any(i["type"] == "ipv4" for i in iocs):
        for ip in [i["value"] for i in iocs if i["type"] == "ipv4"][:2]:
            immediate_actions.append(f"Block IP {ip} at firewall")
    if cves:
        for cve in cves[:2]:
            immediate_actions.append(f"Patch {cve['id']} immediately")
    if not immediate_actions:
        immediate_actions = ["Investigate identified indicators", "Check SIEM for related activity", "Brief security team"]

    return {
        "summary": summary,
        "attack_scenario": f"Based on the identified indicators, an attacker may leverage these IOCs to gain initial access to the network. "
                          f"{'The presence of ' + cves[0]['id'] + ' suggests exploitation of known vulnerabilities. ' if cves else ''}"
                          f"Further lateral movement and data exfiltration are likely objectives.",
        "business_impact": "Successful exploitation could result in unauthorized access to sensitive systems, "
                          "data exfiltration, operational disruption, and potential regulatory compliance violations.",
        "immediate_actions": immediate_actions[:4],
        "long_term_remediation": [
            "Implement defense-in-depth security architecture",
            "Deploy advanced email filtering with phishing detection",
            "Establish vulnerability management SLA for critical CVEs",
            "Conduct regular security awareness training",
        ],
        "monitoring": [
            f"Monitor DNS queries for identified malicious domains" if any(i["type"] == "domain" for i in iocs) else "Monitor for anomalous DNS activity",
            "Search SIEM for connections to identified malicious IPs",
            "Watch for lateral movement indicators",
            "Monitor for data exfiltration patterns",
        ],
    }
