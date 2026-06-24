# Project Overview

## Problem Statement

SOC analysts spend hours manually analyzing threat reports, extracting indicators of compromise, and creating detection rules. This manual workflow is slow, inconsistent, and difficult to scale across high-volume threat feeds and diverse input formats.

The project addresses the need for a faster, more reliable way to convert raw threat data into SOC-ready intelligence and detection artifacts.

## Solution Approach

This platform uses a modular threat intelligence pipeline:

- Ingests multiple input types: raw text, CVE IDs, and uploaded files (`PDF`, `DOCX`, `TXT`, `CSV`, `JSON`).
- Extracts IOCs using regex-based detection for domains, IPs, URLs, hashes, emails, and CVEs.
- Enriches extracted data with local threat intelligence: CVE details, CVSS scores, exploit availability, malware families, and threat actors.
- Maps behavior to MITRE ATT&CK using AI-assisted analysis plus deterministic keyword fallback.
- Generates explainable risk scores and a detailed intelligence report.
- Produces SOC-ready detection rules in Sigma and YARA formats.

The design combines AI intelligence with local heuristics so the application remains useful even when external AI access is limited.

## Key Features

- **Multi-Input Threat Ingestion** — Accepts text, CVE IDs, and file uploads.
- **IOC Extraction Engine** — Automatically detects IPs, domains, hashes, CVEs, URLs, and emails.
- **Threat Enrichment** — Enriches findings with CVE metadata, CVSS, exploit status, malware families, and threat actor context.
- **MITRE ATT&CK Mapping** — Identifies techniques and attack patterns with AI-backed mapping.
- **Risk Scoring Engine** — Produces a 0–100 explainable risk score with factor breakdown.
- **AI Intelligence Report** — Generates human-readable threat summaries and remediation guidance.
- **Detection Rule Generation** — Creates Sigma and YARA rules for SOC deployment.
- **History Persistence** — Stores analysis history in SQLite for review and auditing.
- **Fast Demo Support** — Uses local caches and JSON DBs to avoid external rate limits.

## Short Explanation

### Problem solved

This platform solves the manual, time-consuming process SOC analysts use to convert raw threat data into actionable intelligence. It reduces analyst workload by automating IOC extraction, threat enrichment, MITRE mapping, risk scoring, reporting, and rule generation.

### Approach and design

- Modular pipeline with dedicated services for extraction, enrichment, mapping, scoring, reporting, and rules.
- Hybrid AI design: Gemini-driven analysis with keyword fallback for reliability.
- Local enrichment databases to keep the system fast and demo-friendly.
- Web-based architecture: React + Vite frontend with FastAPI backend.
- Persistent storage in SQLite for analysis records.

### Technologies used

- Backend: `Python 3.11+`, `FastAPI`
- AI: `Google Gemini` via `google-generativeai`
- Database: `SQLite`
- File parsing: `PyPDF2`, `python-docx`
- Frontend: `React`, `Vite`, `Tailwind CSS`, `Recharts`
- Support libraries: `uvicorn`, `python-multipart`, `python-dotenv`, `aiofiles`, `pydantic`, `axios`

### Challenges faced

- Extracting IOCs accurately while avoiding false positives from normal text.
- Structuring AI prompts to yield consistent, usable JSON output.
- Building an explainable risk score that handles edge cases and remains transparent.
- Ensuring functionality without external AI access through robust fallback logic.
- Generating practical Sigma and YARA rules from unstructured threat data.
