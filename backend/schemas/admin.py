from datetime import datetime
from typing import Optional, Dict, Any, List
import re
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator, HttpUrl

from backend.schemas.auth import UserResponse


class AdminUserUpdate(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None


class UserAdminView(BaseModel):
    id: int
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    email_verified: bool
    total_analyses: int = 0
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class PaginatedUsersResponse(BaseModel):
    items: List[UserAdminView]
    total: int
    page: int
    page_size: int
    total_pages: int


class AuditLogResponse(BaseModel):
    id: int
    user_id: Optional[int]
    username: Optional[str] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    ip_address: Optional[str]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PaginatedAuditLogsResponse(BaseModel):
    items: List[AuditLogResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class AdminAnalysisItem(BaseModel):
    id: int
    app_name: str
    package_name: str
    user_id: int
    user_email: str
    total_permissions: int
    dangerous_count: int
    risk_score: float
    risk_level: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PaginatedAnalysesResponse(BaseModel):
    items: List[AdminAnalysisItem]
    total: int
    page: int
    page_size: int
    total_pages: int


class PermissionDetectionStats(BaseModel):
    total_permissions_detected: int
    dangerous_count: int
    normal_count: int
    special_count: int
    unknown_count: int
    top_detected_permissions: List[Dict[str, Any]]
    top_unknown_permissions: List[Dict[str, Any]]


class SystemStatsResponse(BaseModel):
    total_users: int
    active_users: int
    inactive_users: int
    total_analyses: int
    critical_risk_count: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    average_risk_score: float
    permission_statistics: PermissionDetectionStats
    top_dangerous_permissions: List[Dict[str, Any]]
    recent_audit_events: List[Dict[str, Any]]
    recent_analyses: List[Dict[str, Any]]
    system_health: Dict[str, Any]


class SystemHealthResponse(BaseModel):
    status: str
    database: Dict[str, Any]
    knowledge_base: Dict[str, Any]
    storage: Dict[str, Any]
    security: Dict[str, Any]
    timestamp: str


# =============================================================================
# PERMISSION KNOWLEDGE BASE SCHEMAS & VALIDATION
# =============================================================================

VALID_PROTECTION_LEVELS = {
    "dangerous", "normal", "signature", "signatureorsystem",
    "special", "internal", "privileged", "unknown"
}

VALID_RISK_LEVELS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN", "CONTEXT_DEPENDENT"}


class PermissionKBEntrySchema(BaseModel):
    permission: str = Field(..., description="Canonical permission identifier e.g. android.permission.CAMERA")
    category: str = Field(..., min_length=2, description="Functional permission category")
    display_name: str = Field(..., min_length=2, description="Human-readable title")
    description: str = Field(..., min_length=10, description="Plain-language description of requested capability")
    privacy_implications: List[str] = Field(..., min_length=1, description="List of concrete privacy implications")
    sensitive_data: List[str] = Field(..., min_length=1, description="List of sensitive data types accessible")
    protection_level: str = Field(..., description="Android protection level")
    platform_context: str = Field(..., min_length=10, description="OS context, runtime requirements, or API deprecation notes")
    documentation_url: str = Field(..., description="Official developer documentation URL")
    risk_level: str = Field(..., description="Risk assessment level")
    explanation: Optional[str] = Field(default=None, description="Objective explainability statement")

    @model_validator(mode="after")
    def set_default_explanation(self) -> "PermissionKBEntrySchema":
        if not self.explanation or not self.explanation.strip():
            self.explanation = (
                f"This application declares {self.display_name}. "
                f"This declaration alone does not prove that the capability has been used or granted at runtime."
            )
        elif len(self.explanation.strip()) < 10:
            raise ValueError("explanation must be at least 10 characters long if provided.")
        return self

    @field_validator("permission")
    @classmethod
    def validate_permission_id(cls, v: str) -> str:
        v = v.strip()
        if not v or " " in v or "." not in v:
            raise ValueError("Permission identifier must be a valid dotted namespace (e.g. android.permission.CAMERA)")
        return v

    @field_validator("protection_level")
    @classmethod
    def validate_protection_level(cls, v: str) -> str:
        clean = v.strip().lower()
        if clean not in VALID_PROTECTION_LEVELS:
            raise ValueError(f"Invalid protection_level '{v}'. Must be one of: {sorted(VALID_PROTECTION_LEVELS)}")
        return clean

    @field_validator("risk_level")
    @classmethod
    def validate_risk_level(cls, v: str) -> str:
        clean = v.strip().upper()
        if clean not in VALID_RISK_LEVELS:
            raise ValueError(f"Invalid risk_level '{v}'. Must be one of: {sorted(VALID_RISK_LEVELS)}")
        return clean

    @field_validator("documentation_url")
    @classmethod
    def validate_doc_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("http://") and not v.startswith("https://"):
            raise ValueError("documentation_url must be an absolute URL starting with http:// or https://")
        return v

    @field_validator("privacy_implications", "sensitive_data")
    @classmethod
    def validate_non_empty_items(cls, v: List[str]) -> List[str]:
        cleaned = [item.strip() for item in v if item and item.strip()]
        if not cleaned:
            raise ValueError("Must contain at least one non-empty string entry.")
        return cleaned


class KBValidationResponse(BaseModel):
    valid: bool
    permission: Optional[str] = None
    errors: List[str] = []
    message: str


class KBMetadataResponse(BaseModel):
    version: str
    total_entries: int
    last_modified: str
    checksum: str
    categories: List[str]
    schema_status: str
