from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

class ManifestTextAnalysisRequest(BaseModel):
    manifest_xml: str = Field(..., min_length=10, description="Raw AndroidManifest.xml string")
    privacy_policy_text: Optional[str] = Field(None, description="Optional raw privacy policy text for discrepancy audit")

class PermissionDetail(BaseModel):
    name: str
    short_name: str
    group: str
    protection_level: str
    description: str
    privacy_risk: str
    abuse_scenarios: List[str]
    severity_score: float
    remediation: str
    policy_disclosed: bool = False
    discrepancy_status: str = "NORMAL"
    declaration_type: Optional[str] = "uses-permission"
    source_reference: Optional[str] = None
    max_sdk_version: Optional[int] = None
    is_duplicate: bool = False
    platform_context: Optional[str] = None
    documentation_url: Optional[str] = None
    sensitive_data: List[str] = []
    explanation: Optional[str] = None

class StructuredPermissionRecord(BaseModel):
    permission_name: str
    declaration_type: str = "uses-permission"
    max_sdk_version: Optional[int] = None
    source_file: str = "AndroidManifest.xml"
    source_reference: str
    is_duplicate: bool = False
    category: str = "Unknown"
    protection_level: str = "unknown"
    risk_level: str = "UNKNOWN"
    explanation: Optional[str] = None
    privacy_implications: List[str] = []
    sensitive_data: List[str] = []
    documentation_url: Optional[str] = None
    platform_context: Optional[str] = None
    is_known: bool = False

class ManifestAnalysisRequest(BaseModel):
    manifest_xml: str = Field(..., min_length=10, description="Raw AndroidManifest.xml string")
    privacy_policy_text: Optional[str] = Field(None, description="Optional raw privacy policy text")
    source_file: Optional[str] = Field("AndroidManifest.xml", description="Source manifest file identifier")

class ManifestAnalysisResult(BaseModel):
    id: Optional[int] = None
    app_name: str
    package_name: str
    version_code: Optional[str] = None
    version_name: Optional[str] = None
    min_sdk_version: Optional[str] = None
    target_sdk_version: Optional[str] = None
    max_sdk_version: Optional[str] = None
    total_permissions: int
    unique_permissions: int
    duplicate_count: int
    dangerous_count: int
    normal_count: int
    special_count: int
    unknown_count: int
    risk_score: float
    risk_level: str
    permissions: List[StructuredPermissionRecord]
    unsupported_declarations: List[Dict[str, Any]] = []
    sdk_warnings: List[str] = []
    source_file: str = "AndroidManifest.xml"
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class ComboFinding(BaseModel):
    id: str
    name: str
    severity: str
    risk_penalty: float
    explanation: str
    matched_permissions: List[str]

class PolicyDiscrepancy(BaseModel):
    permission_name: str
    issue_type: str  # UNDISCLOSED_DANGEROUS_PERMISSION, DECEPTIVE_OMISSION, EXCESSIVE_PRIVILEGE
    severity: str
    explanation: str
    remediation: str

class AnalysisSummary(BaseModel):
    id: int
    app_name: str
    package_name: str
    risk_score: float
    risk_level: str
    total_permissions: int
    dangerous_count: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class AnalysisResponse(BaseModel):
    id: Optional[int] = None
    app_name: str
    package_name: str
    version_code: Optional[str] = None
    version_name: Optional[str] = None
    min_sdk: Optional[str] = None
    target_sdk: Optional[str] = None

    total_permissions: int
    dangerous_count: int
    normal_count: int
    special_count: int

    risk_score: float
    risk_level: str
    exported_components_count: int
    target_sdk_warnings: List[str] = []

    permissions: List[PermissionDetail] = []
    combo_findings: List[ComboFinding] = []
    discrepancies: List[PolicyDiscrepancy] = []
    policy_analysis: Optional[Dict[str, Any]] = None

    pdf_report_path: Optional[str] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class PolicyAnalysisRequest(BaseModel):
    policy_text: str = Field(..., min_length=10, max_length=1_000_000, description="Raw privacy policy text")
    app_name: Optional[str] = Field("Privacy Policy Evaluation", description="Optional application or policy title")
    analysis_id: Optional[int] = Field(None, description="Optional existing analysis ID to associate excerpts with")

class PolicyExcerptRecord(BaseModel):
    exact_text: str
    paragraph_ref: str
    start_offset: int
    end_offset: int
    stance: str

class PolicyDomainFinding(BaseModel):
    domain_key: str
    display_name: str
    description: str
    status: str
    summary: str
    excerpts: List[PolicyExcerptRecord] = []
    disclaimer: str = "A privacy policy declaration reflects developer disclosure or legal representation; it does not prove actual runtime execution or data flows."

class PolicyAnalysisResponse(BaseModel):
    analysis_id: int
    app_name: str
    word_count: int
    character_count: int
    total_paragraphs: int
    transparency_score: float
    addressed_domains_count: int
    missing_domains_count: int
    ai_augmented: bool = False
    ai_status: str = "deterministic_rules"
    overall_summary: str
    domains: Dict[str, PolicyDomainFinding]
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class PurposeComparisonRequest(BaseModel):
    analysis_id: Optional[int] = Field(None, description="Optional existing analysis ID")
    app_name: Optional[str] = Field("Application", description="Application name")
    app_purpose: Optional[str] = Field(None, description="User-provided application purpose")
    permissions: Optional[List[str]] = Field(None, description="List of permission identifiers")
    manifest_xml: Optional[str] = Field(None, description="Optional raw AndroidManifest.xml string")
    privacy_policy_text: Optional[str] = Field(None, description="Optional privacy policy text")

class ExplainableFindingRecord(BaseModel):
    permission: str
    risk_level: str
    finding_category: str
    reason: str
    privacy_implication: str
    purpose_comparison: str
    review_question: str
    evidence_source: str
    source_reference: str
    confidence: str

    model_config = ConfigDict(from_attributes=True)

class PurposeComparisonResponse(BaseModel):
    analysis_id: int
    app_name: str
    app_purpose: str
    total_permissions: int
    overall_risk_level: str
    risk_counts: Dict[str, int]
    category_counts: Dict[str, int]
    policy_provided: bool
    findings: List[ExplainableFindingRecord]
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
