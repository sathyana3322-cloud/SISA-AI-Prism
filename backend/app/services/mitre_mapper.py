"""MITRE ATT&CK Mapper - Maps threats to tactics, techniques, and procedures."""

import json
import os

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

MITRE_DB = None


def _load_mitre_db():
    global MITRE_DB
    filepath = os.path.join(DATA_DIR, "mitre_attack.json")
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            MITRE_DB = json.load(f)
    else:
        MITRE_DB = {}


def _ensure_loaded():
    if MITRE_DB is None:
        _load_mitre_db()


# Keyword to technique mapping for rule-based fallback
KEYWORD_TECHNIQUE_MAP = {
    "phishing": [{"tactic": "Initial Access", "technique": "Phishing", "id": "T1566", "confidence": "high"}],
    "spearphishing": [{"tactic": "Initial Access", "technique": "Phishing: Spearphishing Attachment", "id": "T1566.001", "confidence": "high"}],
    "credential": [{"tactic": "Credential Access", "technique": "Credential Dumping", "id": "T1003", "confidence": "medium"}],
    "credential theft": [{"tactic": "Credential Access", "technique": "Credential Phishing", "id": "T1566.002", "confidence": "high"}],
    "exploit": [{"tactic": "Initial Access", "technique": "Exploit Public-Facing Application", "id": "T1190", "confidence": "high"}],
    "ransomware": [
        {"tactic": "Impact", "technique": "Data Encrypted for Impact", "id": "T1486", "confidence": "high"},
        {"tactic": "Exfiltration", "technique": "Exfiltration Over C2 Channel", "id": "T1041", "confidence": "medium"},
    ],
    "lockbit": [
        {"tactic": "Impact", "technique": "Data Encrypted for Impact", "id": "T1486", "confidence": "high"},
        {"tactic": "Lateral Movement", "technique": "Remote Services", "id": "T1021", "confidence": "medium"},
    ],
    "powershell": [{"tactic": "Execution", "technique": "PowerShell", "id": "T1059.001", "confidence": "high"}],
    "command": [{"tactic": "Execution", "technique": "Command and Scripting Interpreter", "id": "T1059", "confidence": "medium"}],
    "registry": [{"tactic": "Persistence", "technique": "Registry Run Keys", "id": "T1547.001", "confidence": "medium"}],
    "lateral movement": [{"tactic": "Lateral Movement", "technique": "Remote Services", "id": "T1021", "confidence": "medium"}],
    "privilege escalation": [{"tactic": "Privilege Escalation", "technique": "Exploitation for Privilege Escalation", "id": "T1068", "confidence": "medium"}],
    "c2": [{"tactic": "Command and Control", "technique": "Application Layer Protocol", "id": "T1071", "confidence": "medium"}],
    "exfiltration": [{"tactic": "Exfiltration", "technique": "Exfiltration Over C2 Channel", "id": "T1041", "confidence": "medium"}],
    "persistence": [{"tactic": "Persistence", "technique": "Registry Run Keys", "id": "T1547.001", "confidence": "medium"}],
    "malware": [
        {"tactic": "Execution", "technique": "Command and Scripting Interpreter", "id": "T1059", "confidence": "medium"},
        {"tactic": "Persistence", "technique": "Registry Run Keys", "id": "T1547.001", "confidence": "low"},
    ],
    "brute force": [{"tactic": "Credential Access", "technique": "Brute Force", "id": "T1110", "confidence": "high"}],
    "dns": [{"tactic": "Command and Control", "technique": "Application Layer Protocol: DNS", "id": "T1071.004", "confidence": "medium"}],
    "remote desktop": [{"tactic": "Lateral Movement", "technique": "Remote Desktop Protocol", "id": "T1021.001", "confidence": "high"}],
    "rdp": [{"tactic": "Lateral Movement", "technique": "Remote Desktop Protocol", "id": "T1021.001", "confidence": "high"}],
    "supply chain": [{"tactic": "Initial Access", "technique": "Supply Chain Compromise", "id": "T1195", "confidence": "high"}],
    "watering hole": [{"tactic": "Initial Access", "technique": "Drive-by Compromise", "id": "T1189", "confidence": "high"}],
}


def map_by_keywords(text: str) -> list[dict]:
    """Map threats to MITRE ATT&CK using keyword matching."""
    text_lower = text.lower()
    mappings = []
    seen_ids = set()

    for keyword, techniques in KEYWORD_TECHNIQUE_MAP.items():
        if keyword in text_lower:
            for tech in techniques:
                if tech["id"] not in seen_ids:
                    mappings.append(tech)
                    seen_ids.add(tech["id"])

    return mappings


def get_technique_details(technique_id: str) -> dict | None:
    """Get full details for a MITRE technique."""
    _ensure_loaded()
    return MITRE_DB.get(technique_id)


def map_threats_to_mitre(text: str, ai_mappings: list[dict] | None = None) -> list[dict]:
    """
    Map threats to MITRE ATT&CK framework.
    Uses AI mappings if provided, with keyword-based fallback.
    """
    if ai_mappings:
        # Deduplicate AI mappings
        seen_ids = set()
        unique_mappings = []
        for m in ai_mappings:
            if m.get("id") not in seen_ids:
                unique_mappings.append(m)
                seen_ids.add(m.get("id"))
        return unique_mappings

    # Fallback to keyword-based mapping
    return map_by_keywords(text)
