"""Pydantic models for request/response schemas."""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class AnalysisOptions(BaseModel):
    mitre_mapping: bool = True
    generate_rules: bool = True
    risk_scoring: bool = True


class AnalyzeRequest(BaseModel):
    input_type: str = Field(..., description="text, cve, or url")
    content: str = Field(..., min_length=1, description="Threat data to analyze")
    options: AnalysisOptions = AnalysisOptions()


class IOCItem(BaseModel):
    type: str
    value: str
    reputation: str = "unknown"


class CVEEnrichment(BaseModel):
    id: str
    cvss: float
    severity: str
    description: str
    exploit_available: bool = False
    malware_families: list[str] = []
    threat_actors: list[str] = []


class EnrichmentData(BaseModel):
    cves: list[CVEEnrichment] = []


class MITREMapping(BaseModel):
    tactic: str
    technique: str
    id: str
    confidence: str = "high"


class RiskFactor(BaseModel):
    factor: str
    score: int


class AIReport(BaseModel):
    summary: str
    attack_scenario: str
    business_impact: str
    immediate_actions: list[str]
    long_term_remediation: list[str]
    monitoring: list[str]


class DetectionRules(BaseModel):
    sigma: str
    yara: Optional[str] = None


class AnalysisResponse(BaseModel):
    analysis_id: str
    timestamp: str
    input_text: str = ""
    iocs: list[IOCItem] = []
    enrichment: EnrichmentData = EnrichmentData()
    mitre_mapping: list[MITREMapping] = []
    risk_score: int = 0
    risk_level: str = "low"
    risk_factors: list[RiskFactor] = []
    ai_report: Optional[AIReport] = None
    detection_rules: Optional[DetectionRules] = None


class AnalysisListItem(BaseModel):
    analysis_id: str
    timestamp: str
    input_preview: str
    risk_score: int
    risk_level: str


class AnalysisListResponse(BaseModel):
    analyses: list[AnalysisListItem]
    total: int
    page: int
    page_size: int
