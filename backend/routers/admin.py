from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.database import get_db
from backend.models.user import User
from backend.models.analysis import Analysis
from backend.models.permission import Permission
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
    return db.query(User).order_by(User.created_at.desc()).all()

@router.patch("/users/{user_id}", response_model=UserResponse)
def update_user_status(
    user_id: int,
    req: AdminUserUpdate,
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
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
        resource_type="USER",
        resource_id=str(target.id)
    )

    return target

@router.get("/stats", response_model=SystemStatsResponse)
def get_system_stats(
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    total_users = db.query(func.count(User.id)).scalar() or 0
    total_analyses = db.query(func.count(Analysis.id)).scalar() or 0

    critical_risk = db.query(func.count(Analysis.id)).filter(Analysis.risk_level == "CRITICAL").scalar() or 0
    high_risk = db.query(func.count(Analysis.id)).filter(Analysis.risk_level == "HIGH").scalar() or 0
    medium_risk = db.query(func.count(Analysis.id)).filter(Analysis.risk_level == "MEDIUM").scalar() or 0
    low_risk = db.query(func.count(Analysis.id)).filter(Analysis.risk_level == "LOW").scalar() or 0

    avg_score = db.query(func.avg(Analysis.risk_score)).scalar() or 0.0

    # Aggregate top dangerous permissions directly from the normalized permissions table
    top_perm_rows = db.query(
        Permission.short_name,
        func.count(Permission.id).label("freq")
    ).filter(
        Permission.protection_level.in_(["dangerous", "special", "signature/special"])
    ).group_by(
        Permission.short_name
    ).order_by(
        func.count(Permission.id).desc()
    ).limit(8).all()

    top_perms = [
        {"permission": row[0], "frequency": row[1]}
        for row in top_perm_rows
    ]

    # Recent audit events
    audit_rows = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(10).all()
    recent_events = [
        {
            "action": a.action,
            "target": f"{a.resource_type}:{a.resource_id}",
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
    entries = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
    results = []
    for e in entries:
        username = e.user.email if e.user else "Anonymous/System"
        results.append(AuditLogResponse(
            id=e.id,
            user_id=e.user_id,
            username=username,
            action=e.action,
            resource_type=e.resource_type,
            resource_id=e.resource_id,
            ip_address=e.ip_address,
            created_at=e.created_at
        ))
    return results
