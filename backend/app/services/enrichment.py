"""Threat Enrichment Engine - Adds context to extracted IOCs."""

import json
import os

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")


def _load_json(filename: str) -> dict:
    filepath = os.path.join(DATA_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return json.load(f)
    return {}


# Load enrichment data
CVE_DB = None
MALWARE_DB = None
THREAT_ACTORS_DB = None
IOC_REPUTATION_DB = None


def _ensure_loaded():
    global CVE_DB, MALWARE_DB, THREAT_ACTORS_DB, IOC_REPUTATION_DB
    if CVE_DB is None:
        CVE_DB = _load_json("cve_database.json")
    if MALWARE_DB is None:
        MALWARE_DB = _load_json("malware_families.json")
    if THREAT_ACTORS_DB is None:
        THREAT_ACTORS_DB = _load_json("threat_actors.json")
    if IOC_REPUTATION_DB is None:
        IOC_REPUTATION_DB = _load_json("ioc_reputation.json")


def enrich_cve(cve_id: str) -> dict | None:
    """Enrich a CVE with details from local database."""
    _ensure_loaded()
    return CVE_DB.get(cve_id)


def get_ioc_reputation(ioc_type: str, value: str) -> str:
    """Get reputation score for an IOC."""
    _ensure_loaded()
    rep = IOC_REPUTATION_DB.get(value)
    if rep:
        return rep.get("reputation", "unknown")
    # Heuristic-based reputation
    if ioc_type == "cve":
        return "critical"
    if ioc_type in ("md5", "sha1", "sha256"):
        return "suspicious"
    return "unknown"


def get_malware_families(cve_id: str) -> list[str]:
    """Get associated malware families for a CVE."""
    _ensure_loaded()
    cve_data = CVE_DB.get(cve_id, {})
    return cve_data.get("malware_families", [])


def get_threat_actors(cve_id: str) -> list[str]:
    """Get associated threat actors for a CVE."""
    _ensure_loaded()
    cve_data = CVE_DB.get(cve_id, {})
    return cve_data.get("threat_actors", [])


def enrich_iocs(iocs: list[dict]) -> tuple[list[dict], dict]:
    """
    Enrich a list of IOCs with reputation and CVE details.
    Returns (enriched_iocs, enrichment_data).
    """
    _ensure_loaded()
    enriched_iocs = []
    cve_enrichments = []

    for ioc in iocs:
        ioc_type = ioc["type"]
        value = ioc["value"]

        # Get reputation
        reputation = get_ioc_reputation(ioc_type, value)
        enriched_ioc = {**ioc, "reputation": reputation}

        # If it's a CVE, add CVSS info
        if ioc_type == "cve":
            cve_data = enrich_cve(value)
            if cve_data:
                enriched_ioc["cvss"] = cve_data.get("cvss", 0)
                enriched_ioc["severity"] = cve_data.get("severity", "unknown")
                cve_enrichments.append({
                    "id": value,
                    "cvss": cve_data.get("cvss", 0),
                    "severity": cve_data.get("severity", "unknown"),
                    "description": cve_data.get("description", ""),
                    "exploit_available": cve_data.get("exploit_available", False),
                    "malware_families": cve_data.get("malware_families", []),
                    "threat_actors": cve_data.get("threat_actors", []),
                })

        enriched_iocs.append(enriched_ioc)

    enrichment_data = {"cves": cve_enrichments}
    return enriched_iocs, enrichment_data
