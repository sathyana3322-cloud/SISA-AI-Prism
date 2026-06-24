"""IOC Extraction Engine - Extracts Indicators of Compromise using regex."""

import re
from typing import List


IOC_PATTERNS = {
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "domain": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|info|biz|xyz|top|site|online|club|ru|cn|tk|ml|ga|cf|gq|cc|pw|uk|de|fr|jp|br|in|au|us|ca|edu|gov|mil)\b",
    "url": r"https?://[^\s<>\"']+",
    "email": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "cve": r"CVE-\d{4}-\d{4,7}",
}

# Common false positive patterns to filter out
FALSE_POSITIVES = {
    "ipv4": {"0.0.0.0", "127.0.0.1", "255.255.255.255", "192.168.0.1", "10.0.0.1"},
    "domain": {"example.com", "localhost.com", "test.com"},
}


def extract_iocs(text: str) -> list[dict]:
    """
    Extract IOCs from raw text input.
    Returns list of dicts with type, value.
    """
    iocs = []
    seen_values = set()

    # Extract URLs first (they contain domains/IPs we should not double-count)
    url_matches = set(re.findall(IOC_PATTERNS["url"], text))
    for url in url_matches:
        if url not in seen_values:
            iocs.append({"type": "url", "value": url})
            seen_values.add(url)

    # Extract CVEs
    cve_matches = set(re.findall(IOC_PATTERNS["cve"], text))
    for cve in cve_matches:
        if cve not in seen_values:
            iocs.append({"type": "cve", "value": cve})
            seen_values.add(cve)

    # Extract emails
    email_matches = set(re.findall(IOC_PATTERNS["email"], text))
    for email in email_matches:
        if email not in seen_values:
            iocs.append({"type": "email", "value": email})
            seen_values.add(email)

    # Extract hashes (order matters: sha256 > sha1 > md5)
    sha256_matches = set(re.findall(IOC_PATTERNS["sha256"], text))
    for h in sha256_matches:
        if h not in seen_values:
            iocs.append({"type": "sha256", "value": h})
            seen_values.add(h)

    sha1_matches = set(re.findall(IOC_PATTERNS["sha1"], text))
    for h in sha1_matches:
        if h not in seen_values and h not in {s[:40] for s in sha256_matches}:
            iocs.append({"type": "sha1", "value": h})
            seen_values.add(h)

    md5_matches = set(re.findall(IOC_PATTERNS["md5"], text))
    for h in md5_matches:
        if h not in seen_values and h not in {s[:32] for s in sha1_matches} and h not in {s[:32] for s in sha256_matches}:
            iocs.append({"type": "md5", "value": h})
            seen_values.add(h)

    # Extract IPs (skip those already in URLs)
    ip_matches = set(re.findall(IOC_PATTERNS["ipv4"], text))
    for ip in ip_matches:
        if ip not in seen_values and ip not in FALSE_POSITIVES.get("ipv4", set()):
            # Check if IP is already part of a URL
            in_url = any(ip in url for url in url_matches)
            if not in_url:
                iocs.append({"type": "ipv4", "value": ip})
                seen_values.add(ip)

    # Extract domains (skip those in URLs/emails)
    domain_matches = set(re.findall(IOC_PATTERNS["domain"], text))
    for domain in domain_matches:
        if domain not in seen_values and domain not in FALSE_POSITIVES.get("domain", set()):
            # Skip if domain is part of a URL or email already extracted
            in_url = any(domain in url for url in url_matches)
            in_email = any(domain in email for email in email_matches)
            if not in_url and not in_email:
                iocs.append({"type": "domain", "value": domain})
                seen_values.add(domain)

    return iocs
