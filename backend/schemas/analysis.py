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
