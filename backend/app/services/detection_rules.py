"""Detection Rule Generator - Generates Sigma and YARA rules from analysis."""

import yaml


def generate_sigma_rule(iocs: list[dict], mitre_mappings: list[dict], text: str = "") -> str:
    """Generate a Sigma detection rule from extracted IOCs."""
    domains = [i["value"] for i in iocs if i["type"] == "domain"]
    ips = [i["value"] for i in iocs if i["type"] == "ipv4"]
    hashes = [i["value"] for i in iocs if i["type"] in ("md5", "sha1", "sha256")]
    urls = [i["value"] for i in iocs if i["type"] == "url"]

    # Determine rule title based on context
    title = "Suspicious Communication with Threat Infrastructure"
    if "phishing" in text.lower():
        title = "Suspicious Communication with Phishing Infrastructure"
    elif "ransomware" in text.lower() or "lockbit" in text.lower():
        title = "Ransomware C2 Communication Detected"
    elif "malware" in text.lower():
        title = "Malware Infrastructure Communication"

    # Build MITRE tags
    tags = []
    for m in mitre_mappings[:5]:
        tactic_tag = m["tactic"].lower().replace(" ", "_")
        tech_id = m["id"].lower()
        tags.append(f"attack.{tactic_tag}")
        tags.append(f"attack.{tech_id}")
    # Deduplicate
    tags = list(dict.fromkeys(tags))

    # Build the rule as a dict first
    rule = {
        "title": title,
        "id": None,
        "status": "experimental",
        "description": f"Detects network communication with identified threat infrastructure",
        "references": [],
        "tags": tags if tags else ["attack.initial_access"],
        "logsource": {},
        "detection": {},
        "level": "high",
        "falsepositives": ["Legitimate services using same infrastructure"],
    }

    # Build detection logic based on available IOCs
    detection_parts = {}
    conditions = []

    if domains:
        rule["logsource"] = {"category": "proxy"}
        detection_parts["selection_domain"] = {
            "url|contains": domains
        }
        conditions.append("selection_domain")

    if ips:
        if not rule["logsource"]:
            rule["logsource"] = {"category": "firewall"}
        detection_parts["selection_ip"] = {
            "dst_ip": ips
        }
        conditions.append("selection_ip")

    if hashes:
        if not rule["logsource"]:
            rule["logsource"] = {"category": "process_creation", "product": "windows"}
        detection_parts["selection_hash"] = {
            "Hashes|contains": hashes
        }
        conditions.append("selection_hash")

    if not conditions:
        # Fallback generic rule
        rule["logsource"] = {"category": "proxy"}
        detection_parts["selection"] = {"url|contains": ["placeholder-indicator.com"]}
        conditions = ["selection"]

    detection_parts["condition"] = " or ".join(conditions)
    rule["detection"] = detection_parts

    # Convert to YAML-like string
    return _rule_to_sigma_yaml(rule)


def _rule_to_sigma_yaml(rule: dict) -> str:
    """Convert rule dict to Sigma YAML format."""
    lines = []
    lines.append(f"title: {rule['title']}")
    lines.append(f"status: {rule['status']}")
    lines.append(f"description: {rule['description']}")
    lines.append("logsource:")
    for k, v in rule["logsource"].items():
        lines.append(f"    {k}: {v}")
    lines.append("detection:")
    for key, value in rule["detection"].items():
        if key == "condition":
            lines.append(f"    condition: {value}")
        else:
            lines.append(f"    {key}:")
            for field, vals in value.items():
                lines.append(f"        {field}:")
                if isinstance(vals, list):
                    for v in vals:
                        lines.append(f"            - {v}")
                else:
                    lines.append(f"            - {vals}")
    lines.append(f"level: {rule['level']}")
    if rule.get("tags"):
        lines.append("tags:")
        for tag in rule["tags"]:
            lines.append(f"    - {tag}")
    lines.append("falsepositives:")
    for fp in rule.get("falsepositives", []):
        lines.append(f"    - {fp}")

    return "\n".join(lines)


def generate_yara_rule(iocs: list[dict], text: str = "") -> str:
    """Generate a YARA rule from extracted IOCs."""
    domains = [i["value"] for i in iocs if i["type"] == "domain"]
    ips = [i["value"] for i in iocs if i["type"] == "ipv4"]
    hashes = [i["value"] for i in iocs if i["type"] in ("md5", "sha1", "sha256")]

    rule_name = "Threat_IOC_Detection"
    if "phishing" in text.lower():
        rule_name = "Phishing_Campaign_Detection"
    elif "ransomware" in text.lower() or "lockbit" in text.lower():
        rule_name = "Ransomware_IOC_Detection"

    lines = [f"rule {rule_name} {{"]
    lines.append("    meta:")
    lines.append(f'        description = "Detects artifacts from identified threat campaign"')
    lines.append(f'        threat_level = "high"')
    lines.append(f'        date = "2026-06-22"')
    lines.append("    strings:")

    idx = 1
    for d in domains[:5]:
        lines.append(f'        $domain{idx} = "{d}"')
        idx += 1
    for ip in ips[:5]:
        lines.append(f'        $ip{idx} = "{ip}"')
        idx += 1
    for h in hashes[:3]:
        # Convert first 8 chars to hex bytes for YARA
        hex_bytes = " ".join([h[i:i+2] for i in range(0, min(16, len(h)), 2)])
        lines.append(f"        $hash{idx} = {{ {hex_bytes} }}")
        idx += 1

    if idx == 1:
        lines.append('        $generic = "threat_indicator"')

    lines.append("    condition:")
    lines.append("        any of them")
    lines.append("}")

    return "\n".join(lines)
