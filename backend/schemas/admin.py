from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict
from backend.schemas.auth import UserResponse

class AdminUserUpdate(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None

class SystemStatsResponse(BaseModel):
    total_users: int
    total_analyses: int
    critical_risk_count: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    average_risk_score: float
    top_dangerous_permissions: List[Dict[str, Any]]
    recent_audit_events: List[Dict[str, Any]]

class AuditLogResponse(BaseModel):
    id: int
    user_id: Optional[int]
    username: Optional[str] = None
    action: str
    target_type: Optional[str]
    target_id: Optional[str]
    details: Optional[Dict[str, Any]]
    ip_address: Optional[str]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
