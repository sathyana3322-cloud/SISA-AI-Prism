# AI-Powered Threat Intelligence & Attack Mapping Platform

An AI-powered cybersecurity intelligence platform that ingests threat data (CVEs, IOCs, threat reports), extracts indicators, maps them to MITRE ATT&CK, scores risk, and generates actionable intelligence reports with detection rules.

## Problem Statement

SOC analysts spend hours manually analyzing threat reports, extracting IOCs, and creating detection rules. This platform automates the entire workflow — from raw threat data to SOC-ready intelligence — in seconds.

## Key Features

- **Multi-Input Threat Ingestion** — Paste text, enter CVE IDs, or upload files (PDF, DOCX, TXT, CSV, JSON)
- **IOC Extraction Engine** — Automatically extracts IPs, domains, hashes, CVEs, URLs, emails using regex
- **Threat Enrichment** — CVE details, CVSS scores, exploit availability, malware families, threat actors
- **MITRE ATT&CK Mapping** — AI-powered technique identification with visual attack chain
- **Risk Scoring Engine** — 0-100 explainable risk score with factor breakdown
- **AI Intelligence Report** — Gemini-generated threat summary, attack scenarios, business impact, remediation
- **Detection Rule Generation** — Sigma and YARA rules ready for SOC deployment

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11+, FastAPI |
| Frontend | React + Vite, Tailwind CSS, Recharts |
| AI | Google Gemini 1.5 Flash |
| Database | SQLite |
| File Parsing | PyPDF2, python-docx |

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Google Gemini API key ([get one free](https://aistudio.google.com/app/apikey))

### Setup

```bash
# Clone the repository
git clone <repo-url>
cd hackathan_threat_intelligence

# Backend setup
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure API key
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY

# Start backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Frontend setup (new terminal)
cd frontend
npm install
npm run dev
```

### Access

- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/analyze-threat` | Analyze text-based threat data |
| POST | `/api/analyze-threat/upload` | Analyze uploaded file |
| GET | `/api/analyses` | List analysis history |
| GET | `/api/analyses/{id}` | Get specific analysis |
| GET | `/health` | Health check |

## Architecture

```
Frontend (React + Vite)
    ↓ REST API
Backend (FastAPI)
    ↓ Processing Pipeline
    ├── IOC Extractor (regex)
    ├── Threat Enrichment (local JSON DB)
    ├── MITRE ATT&CK Mapper (AI + keyword fallback)
    ├── Risk Scorer (weighted factors)
    ├── AI Report Generator (Gemini)
    └── Detection Rule Generator (Sigma/YARA)
    ↓
    SQLite (persistence) + Gemini API (AI)
```

## Design Decisions

- **Local enrichment DB** over external APIs — faster, no rate limits during demo
- **AI + keyword fallback** for MITRE mapping — works even without API key
- **In-memory caching** for AI responses — same input doesn't re-call API
- **Modular pipeline** — each engine is a separate service module

## Challenges Faced

1. Balancing IOC extraction precision (avoiding false positives on normal text)
2. Structuring AI prompts for consistent JSON output from Gemini
3. Making the risk scoring explainable while handling edge cases

## Demo

Paste this into the text field:
```
A phishing campaign targets finance users.
Domain: secure-login-update.com
IP: 185.199.108.153
Exploited Vulnerability: CVE-2023-3519
Attack Goal: Credential Theft
```

Expected output: Risk Score 88-90/100 (Critical), 3 IOCs extracted, 4 MITRE techniques mapped, full AI report, Sigma + YARA rules generated.
