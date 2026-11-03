from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.database import get_db
from backend.models.user import User
from backend.models.analysis import AnalysisRecord
from backend.models.audit_log import AuditLog
from backend.schemas.auth import UserResponse
from backend.schemas.admin import AdminUserUpdate, SystemStatsResponse, AuditLogResponse
from backend.security.dependencies import get_current_admin
from backend.services.audit_service import log_audit_event

router = APIRouter(prefix="/admin", tags=["Admin Management"])

@router.get("/users", response_model=List[UserResponse])
def get_all_users(
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """
    List all registered platform users.
    """
    return db.query(User).order_by(User.created_at.desc()).all()

@router.patch("/users/{user_id}", response_model=UserResponse)
def update_user_status(
    user_id: int,
    req: AdminUserUpdate,
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """
    Update user role or active status.
    """
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")

    if target.id == admin_user.id and req.is_active is False:
        raise HTTPException(status_code=400, detail="Administrators cannot deactivate their own account.")

    if req.role is not None:
        if req.role not in ("user", "admin"):
            raise HTTPException(status_code=400, detail="Invalid role specified. Must be 'user' or 'admin'.")
        target.role = req.role

    if req.is_active is not None:
        target.is_active = req.is_active

    db.commit()
    db.refresh(target)

    log_audit_event(
        db,
        action="ADMIN_UPDATE_USER",
        user_id=admin_user.id,
        target_type="USER",
        target_id=str(target.id),
        details={"new_role": target.role, "new_active": target.is_active}
    )

    return target

@router.get("/stats", response_model=SystemStatsResponse)
def get_system_stats(
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """
    Aggregate cross-application security metrics and system telemetry.
    """
    total_users = db.query(func.count(User.id)).scalar() or 0
    total_analyses = db.query(func.count(AnalysisRecord.id)).scalar() or 0

    critical_risk = db.query(func.count(AnalysisRecord.id)).filter(AnalysisRecord.risk_level == "CRITICAL").scalar() or 0
    high_risk = db.query(func.count(AnalysisRecord.id)).filter(AnalysisRecord.risk_level == "HIGH").scalar() or 0
    medium_risk = db.query(func.count(AnalysisRecord.id)).filter(AnalysisRecord.risk_level == "MEDIUM").scalar() or 0
    low_risk = db.query(func.count(AnalysisRecord.id)).filter(AnalysisRecord.risk_level == "LOW").scalar() or 0

    avg_score = db.query(func.avg(AnalysisRecord.risk_score)).scalar() or 0.0

    # Aggregate top dangerous permissions
    all_records = db.query(AnalysisRecord.manifest_data).all()
    perm_counter: Dict[str, int] = {}
    for (m_data,) in all_records:
        if m_data and "permissions" in m_data:
            for p in m_data["permissions"]:
                if p.get("protection_level") in ("dangerous", "special"):
                    p_name = p.get("short_name", p.get("name", "Unknown"))
                    perm_counter[p_name] = perm_counter.get(p_name, 0) + 1

    top_perms = [
        {"permission": k, "frequency": v}
        for k, v in sorted(perm_counter.items(), key=lambda x: x[1], reverse=True)[:8]
    ]

    # Recent audit events
    audit_rows = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(10).all()
    recent_events = [
        {
            "action": a.action,
            "target": f"{a.target_type}:{a.target_id}",
            "ip": a.ip_address,
            "timestamp": a.created_at.strftime("%Y-%m-%d %H:%M")
        }
        for a in audit_rows
    ]

    return {
        "total_users": total_users,
        "total_analyses": total_analyses,
        "critical_risk_count": critical_risk,
        "high_risk_count": high_risk,
        "medium_risk_count": medium_risk,
        "low_risk_count": low_risk,
        "average_risk_score": round(float(avg_score), 1),
        "top_dangerous_permissions": top_perms,
        "recent_audit_events": recent_events
    }

@router.get("/audit-logs", response_model=List[AuditLogResponse])
def get_audit_logs(
    limit: int = 50,
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """
    Retrieve system security audit trail.
    """
    entries = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
    results = []
    for e in entries:
        username = e.user.username if e.user else "Anonymous/System"
        results.append(AuditLogResponse(
            id=e.id,
            user_id=e.user_id,
            username=username,
            action=e.action,
            target_type=e.target_type,
            target_id=e.target_id,
            details=e.details,
            ip_address=e.ip_address,
            created_at=e.created_at
        ))
    return results
