"""Analysis endpoints - Main threat analysis pipeline."""

import uuid
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, UploadFile, File, Form

from app.models.schemas import (
    AnalyzeRequest,
    AnalysisResponse,
    AnalysisOptions,
    IOCItem,
    CVEEnrichment,
    EnrichmentData,
    MITREMapping,
    RiskFactor,
    AIReport,
    DetectionRules,
)
from app.services.ioc_extractor import extract_iocs
from app.services.enrichment import enrich_iocs
from app.services.mitre_mapper import map_threats_to_mitre
from app.services.risk_scorer import calculate_risk_score
from app.services.ai_engine import generate_threat_report, generate_mitre_mappings
from app.services.detection_rules import generate_sigma_rule, generate_yara_rule
from app.services.file_parser import extract_text_from_file
from app.services.database import save_analysis

logger = logging.getLogger(__name__)
router = APIRouter()


def _generate_analysis_id() -> str:
    """Generate a unique analysis ID."""
    now = datetime.now(timezone.utc)
    short_id = uuid.uuid4().hex[:6].upper()
    return f"TI-{now.strftime('%Y%m%d')}-{short_id}"


def _run_pipeline(content: str, input_type: str, options: AnalysisOptions) -> dict:
    """Run the full threat analysis pipeline."""
    analysis_id = _generate_analysis_id()
    timestamp = datetime.now(timezone.utc).isoformat()

    logger.info(f"Starting analysis {analysis_id} - type: {input_type}")

    # Step 1: Extract IOCs
    iocs_raw = extract_iocs(content)
    logger.info(f"Extracted {len(iocs_raw)} IOCs")

    # Step 2: Enrich IOCs
    iocs_enriched, enrichment_data = enrich_iocs(iocs_raw)
    logger.info(f"Enrichment complete: {len(enrichment_data.get('cves', []))} CVEs enriched")

    # Step 3: MITRE ATT&CK Mapping
    mitre_mappings = []
    if options.mitre_mapping:
        # Try AI-based mapping first
        ai_mitre = generate_mitre_mappings(content, iocs_enriched)
        mitre_mappings = map_threats_to_mitre(content, ai_mitre)
        logger.info(f"MITRE mapping: {len(mitre_mappings)} techniques identified")

    # Step 4: Risk Scoring
    risk_score, risk_level, risk_factors = 0, "low", []
    if options.risk_scoring:
        risk_score, risk_level, risk_factors = calculate_risk_score(iocs_enriched, enrichment_data)
        logger.info(f"Risk score: {risk_score} ({risk_level})")

    # Step 5: AI Report Generation
    ai_report = generate_threat_report(content, iocs_enriched, enrichment_data, mitre_mappings)
    logger.info("AI report generated")

    # Step 6: Detection Rule Generation
    detection_rules = None
    if options.generate_rules:
        sigma_rule = generate_sigma_rule(iocs_enriched, mitre_mappings, content)
        yara_rule = generate_yara_rule(iocs_enriched, content)
        detection_rules = {"sigma": sigma_rule, "yara": yara_rule}
        logger.info("Detection rules generated")

    # Build response
    result = {
        "analysis_id": analysis_id,
        "timestamp": timestamp,
        "input_text": content[:500],
        "iocs": iocs_enriched,
        "enrichment": enrichment_data,
        "mitre_mapping": mitre_mappings,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "ai_report": ai_report,
        "detection_rules": detection_rules,
    }

    # Save to database
    save_analysis(analysis_id, timestamp, content[:500], input_type, result)
    logger.info(f"Analysis {analysis_id} saved to database")

    return result


@router.post("/analyze-threat", response_model=AnalysisResponse)
async def analyze_threat(request: AnalyzeRequest):
    """
    Analyze threat data from text input.
    Accepts raw text, CVE IDs, URLs, IPs, or domains.
    """
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Content cannot be empty")

    try:
        result = _run_pipeline(request.content, request.input_type, request.options)
        return result
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/analyze-threat/upload", response_model=AnalysisResponse)
async def analyze_threat_upload(
    file: UploadFile = File(...),
    options: str = Form('{"mitre_mapping": true, "generate_rules": true, "risk_scoring": true}'),
):
    """
    Analyze threat data from file upload.
    Supports PDF, DOC, DOCX, TXT, CSV, JSON.
    """
    # Validate file type
    allowed_extensions = {"pdf", "doc", "docx", "txt", "csv", "json"}
    filename = file.filename or "unknown.txt"
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""

    if ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: .{ext}. Allowed: {', '.join(allowed_extensions)}",
        )

    # Read and parse file
    content_bytes = await file.read()
    if not content_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    # Size limit: 10MB
    if len(content_bytes) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large. Maximum 10MB allowed.")

    text_content = extract_text_from_file(content_bytes, filename)
    if not text_content or not text_content.strip():
        raise HTTPException(status_code=400, detail="Could not extract text from file")

    # Parse options
    import json
    try:
        opts_dict = json.loads(options)
        analysis_options = AnalysisOptions(**opts_dict)
    except (json.JSONDecodeError, ValueError):
        analysis_options = AnalysisOptions()

    try:
        result = _run_pipeline(text_content, "file", analysis_options)
        return result
    except Exception as e:
        logger.error(f"File analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
