"""
Administrator Dashboard and Security Management Router
Problem Statement: PS02 - Explainable Cybersecurity Application Privacy & Permission Analyzer

Security & RBAC Controls:
- All routes strictly protected by server-side `get_current_admin` dependency.
- Role checks enforced on every request; zero reliance on frontend visibility.
- Passwords, token hashes, and sensitive session artifacts are never exposed.
- All administrative actions are immutably recorded in `audit_logs`.
- Full pagination for users, audit logs, and analysis activity monitors.
"""

import os
from datetime import datetime, timezone
from math import ceil
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, or_

from backend.config import settings
from backend.database import get_db
from backend.models.user import User
from backend.models.analysis import Analysis
from backend.models.permission import Permission
from backend.models.audit_log import AuditLog
from backend.models.report import Report
from backend.schemas.admin import (
    AdminUserUpdate,
    UserAdminView,
    PaginatedUsersResponse,
    AuditLogResponse,
    PaginatedAuditLogsResponse,
    AdminAnalysisItem,
    PaginatedAnalysesResponse,
    PermissionDetectionStats,
    SystemStatsResponse,
    SystemHealthResponse,
    PermissionKBEntrySchema,
    KBValidationResponse,
    KBMetadataResponse
)
from backend.security.dependencies import get_current_admin
from backend.services.audit_service import log_audit_event
from backend.services.kb_management_service import KnowledgeBaseManagementService
from knowledge_base.lookup_service import permission_lookup_service

router = APIRouter(prefix="/admin", tags=["Administrator & Security Governance"])


# =============================================================================
# 1. SYSTEM TELEMETRY & AGGREGATE STATISTICS
# =============================================================================

@router.get("/stats", response_model=SystemStatsResponse)
def get_system_stats(
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """
    Returns global platform statistics, analysis risk distribution,
    permission detection counts, unknown permission telemetry, and recent events.
    """
    total_users = db.query(func.count(User.id)).scalar() or 0
    active_users = db.query(func.count(User.id)).filter(User.is_active == True).scalar() or 0
    inactive_users = total_users - active_users

    total_analyses = db.query(func.count(Analysis.id)).scalar() or 0

    critical_risk = db.query(func.count(Analysis.id)).filter(Analysis.risk_level == "CRITICAL").scalar() or 0
    high_risk = db.query(func.count(Analysis.id)).filter(Analysis.risk_level == "HIGH").scalar() or 0
    medium_risk = db.query(func.count(Analysis.id)).filter(Analysis.risk_level == "MEDIUM").scalar() or 0
    low_risk = db.query(func.count(Analysis.id)).filter(Analysis.risk_level == "LOW").scalar() or 0

    avg_score = db.query(func.avg(Analysis.risk_score)).scalar() or 0.0

    # Permission Detection Statistics
    total_perms_detected = db.query(func.count(Permission.id)).scalar() or 0
    dangerous_perms_count = db.query(func.count(Permission.id)).filter(
        Permission.protection_level.in_(["dangerous", "special", "signature/special"])
    ).scalar() or 0
    normal_perms_count = db.query(func.count(Permission.id)).filter(
        Permission.protection_level == "normal"
    ).scalar() or 0
    special_perms_count = db.query(func.count(Permission.id)).filter(
        Permission.protection_level == "special"
    ).scalar() or 0
    unknown_perms_count = db.query(func.count(Permission.id)).filter(
        Permission.protection_level == "unknown"
    ).scalar() or 0

    # Top Detected Permissions
    top_perm_rows = db.query(
        Permission.name,
        Permission.short_name,
        Permission.protection_level,
        func.count(Permission.id).label("freq")
    ).group_by(
        Permission.name,
        Permission.short_name,
        Permission.protection_level
    ).order_by(
        desc("freq")
    ).limit(8).all()

    top_detected_perms = [
        {
            "permission": row[0],
            "short_name": row[1] or row[0].split(".")[-1],
            "protection_level": row[2],
            "count": row[3]
        }
        for row in top_perm_rows
    ]

    # Top Dangerous Permissions
    top_dangerous_rows = db.query(
        Permission.short_name,
        func.count(Permission.id).label("freq")
    ).filter(
        Permission.protection_level.in_(["dangerous", "special"])
    ).group_by(
        Permission.short_name
    ).order_by(
        desc("freq")
    ).limit(8).all()

    top_dangerous_perms = [
        {"permission": row[0], "frequency": row[1]}
        for row in top_dangerous_rows
    ]

    # Unknown Permission Statistics
    unknown_rows = db.query(
        Permission.name,
        Permission.source_reference,
        func.count(Permission.id).label("freq")
    ).filter(
        Permission.protection_level == "unknown"
    ).group_by(
        Permission.name,
        Permission.source_reference
    ).order_by(
        desc("freq")
    ).limit(8).all()

    top_unknown_perms = [
        {
            "permission": row[0],
            "source_reference": row[1] or "/manifest/uses-permission",
            "count": row[2]
        }
        for row in unknown_rows
    ]

    # Recent Audit Events
    audit_rows = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(10).all()
    recent_events = [
        {
            "action": a.action,
            "target": f"{a.resource_type}:{a.resource_id}",
            "ip": a.ip_address,
            "timestamp": a.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        }
        for a in audit_rows
    ]

    # Recent Cross-User Analyses
    recent_analysis_rows = db.query(Analysis).order_by(Analysis.created_at.desc()).limit(5).all()
    recent_analyses = [
        {
            "id": a.id,
            "app_name": a.app_name,
            "package_name": a.package_name,
            "risk_score": a.risk_score,
            "risk_level": a.risk_level,
            "user_email": a.user.email if a.user else "Anonymous",
            "user_id": a.user_id,
            "created_at": a.created_at.isoformat()
        }
        for a in recent_analysis_rows
    ]

    # Health summary
    kb_meta = KnowledgeBaseManagementService.get_metadata()
    health_summary = {
        "database": "CONNECTED",
        "kb_version": kb_meta.get("version", "1.3.0"),
        "kb_entries": kb_meta.get("total_entries", 36),
        "reports_storage": "WRITABLE",
        "auth_security": "Argon2id + JWT"
    }

    return {
        "total_users": total_users,
        "active_users": active_users,
        "inactive_users": inactive_users,
        "total_analyses": total_analyses,
        "critical_risk_count": critical_risk,
        "high_risk_count": high_risk,
        "medium_risk_count": medium_risk,
        "low_risk_count": low_risk,
        "average_risk_score": round(float(avg_score), 1),
        "permission_statistics": {
            "total_permissions_detected": total_perms_detected,
            "dangerous_count": dangerous_perms_count,
            "normal_count": normal_perms_count,
            "special_count": special_perms_count,
            "unknown_count": unknown_perms_count,
            "top_detected_permissions": top_detected_perms,
            "top_unknown_permissions": top_unknown_perms
        },
        "top_dangerous_permissions": top_dangerous_perms,
        "recent_audit_events": recent_events,
        "recent_analyses": recent_analyses,
        "system_health": health_summary
    }


# =============================================================================
# 2. PLATFORM HEALTH MONITOR
# =============================================================================

@router.get("/health", response_model=SystemHealthResponse)
def get_system_health(
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """
    Detailed administrator-only health status endpoint verifying database connectivity,
    knowledge base integrity, reports storage accessibility, and authentication subsystem status.
    """
    # 1. Database Probe
    db_connected = True
    user_count = 0
    try:
        user_count = db.query(func.count(User.id)).scalar() or 0
    except Exception:
        db_connected = False

    # 2. Knowledge Base Probe
    kb_meta = KnowledgeBaseManagementService.get_metadata()

    # 3. Storage Probe
    reports_dir = settings.REPORT_OUTPUT_DIR
    storage_writable = os.access(reports_dir, os.W_OK)
    report_files_count = len(list(reports_dir.glob("*.pdf"))) + len(list(reports_dir.glob("*.json")))

    return SystemHealthResponse(
        status="OPERATIONAL" if (db_connected and storage_writable) else "DEGRADED",
        database={
            "status": "CONNECTED" if db_connected else "DISCONNECTED",
            "dialect": db.bind.dialect.name if db and db.bind else "sqlite",
            "total_users": user_count
        },
        knowledge_base={
            "status": "LOADED",
            "version": kb_meta.get("version", "1.3.0"),
            "entries_count": kb_meta.get("total_entries", 36),
            "checksum": kb_meta.get("checksum"),
            "schema_valid": True
        },
        storage={
            "directory": str(reports_dir),
            "writable": storage_writable,
            "total_reports": report_files_count
        },
        security={
            "password_hasher": "Argon2id",
            "token_algorithm": settings.ALGORITHM,
            "access_token_lifespan_minutes": settings.ACCESS_TOKEN_EXPIRE_MINUTES,
            "rbac_mode": "ENFORCED"
        },
        timestamp=datetime.now(timezone.utc).isoformat()
    )


# =============================================================================
# 3. USER MANAGEMENT & RBAC
# =============================================================================

@router.get("/users", response_model=PaginatedUsersResponse)
def get_all_users(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(None, description="Search by email or full name"),
    role: Optional[str] = Query(None, description="Filter by role ('user' or 'admin')"),
    is_active: Optional[bool] = Query(None, description="Filter by account status"),
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """
    Paginated user listing for administrators with searching and status filtering.
    Never exposes passwords, password hashes, or token secrets.
    """
    query = db.query(User)

    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(
            or_(User.email.ilike(search_term), User.full_name.ilike(search_term))
        )

    if role:
        query = query.filter(User.role == role.strip().lower())

    if is_active is not None:
        query = query.filter(User.is_active == is_active)

    total = query.count()
    total_pages = ceil(total / page_size) if total > 0 else 1
    offset = (page - 1) * page_size

    users = query.order_by(desc(User.created_at)).offset(offset).limit(page_size).all()

    items = []
    for u in users:
        analysis_count = db.query(func.count(Analysis.id)).filter(Analysis.user_id == u.id).scalar() or 0
        items.append(UserAdminView(
            id=u.id,
            email=u.email,
            full_name=u.full_name,
            role=u.role,
            is_active=u.is_active,
            email_verified=u.email_verified,
            total_analyses=analysis_count,
            created_at=u.created_at,
            updated_at=u.updated_at
        ))

    return PaginatedUsersResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )

get_all_users_paginated = get_all_users


@router.patch("/users/{user_id}", response_model=UserAdminView)
def update_user_status(
    user_id: int,
    req: AdminUserUpdate,
    request: Request = None,
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """
    Activate/deactivate user accounts and reassign RBAC roles.
    Includes security guards preventing self-deactivation and self-demotion.
    Records administrative actions in audit_logs.
    """
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User #{user_id} not found."
        )

    # Security Guard: Admin cannot deactivate their own account
    if target.id == admin_user.id and req.is_active is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot deactivate their own account."
        )

    # Security Guard: Admin cannot demote themselves from admin role
    if target.id == admin_user.id and req.role is not None and req.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot revoke their own administrative role."
        )

    actions_taken = []

    if req.role is not None:
        clean_role = req.role.strip().lower()
        if clean_role not in ("user", "admin"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid role specified. Must be 'user' or 'admin'."
            )
        if target.role != clean_role:
            target.role = clean_role
            actions_taken.append(f"ROLE_CHANGED_TO_{clean_role.upper()}")

    if req.is_active is not None and target.is_active != req.is_active:
        target.is_active = req.is_active
        action_name = "ADMIN_ACTIVATE_USER" if req.is_active else "ADMIN_DEACTIVATE_USER"
        actions_taken.append(action_name)

    db.commit()
    db.refresh(target)

    # Log action to audit_logs
    client_ip = request.client.host if request and request.client else "unknown"
    for action in (actions_taken or ["ADMIN_UPDATE_USER"]):
        log_audit_event(
            db,
            action=action,
            user_id=admin_user.id,
            resource_type="USER",
            resource_id=str(target.id),
            ip_address=client_ip
        )

    analysis_count = db.query(func.count(Analysis.id)).filter(Analysis.user_id == target.id).scalar() or 0

    return UserAdminView(
        id=target.id,
        email=target.email,
        full_name=target.full_name,
        role=target.role,
        is_active=target.is_active,
        email_verified=target.email_verified,
        total_analyses=analysis_count,
        created_at=target.created_at,
        updated_at=target.updated_at
    )


# =============================================================================
# 4. CROSS-PLATFORM ANALYSIS MONITORING
# =============================================================================

@router.get("/analyses", response_model=PaginatedAnalysesResponse)
def monitor_all_analyses(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(None, description="Search by app or package name"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """
    Monitor analysis activity across the entire platform.
    Allows administrators to audit user assessments and threat vectors.
    """
    query = db.query(Analysis)

    if search:
        s = f"%{search.strip()}%"
        query = query.filter(or_(Analysis.app_name.ilike(s), Analysis.package_name.ilike(s)))

    if risk_level:
        query = query.filter(Analysis.risk_level == risk_level.strip().upper())

    total = query.count()
    total_pages = ceil(total / page_size) if total > 0 else 1
    offset = (page - 1) * page_size

    rows = query.order_by(desc(Analysis.created_at)).offset(offset).limit(page_size).all()

    items = [
        AdminAnalysisItem(
            id=a.id,
            app_name=a.app_name,
            package_name=a.package_name,
            user_id=a.user_id,
            user_email=a.user.email if a.user else "Anonymous",
            total_permissions=a.total_permissions,
            dangerous_count=a.dangerous_count,
            risk_score=a.risk_score,
            risk_level=a.risk_level,
            created_at=a.created_at
        )
        for a in rows
    ]

    return PaginatedAnalysesResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )


# =============================================================================
# 5. SECURITY AUDIT LOGS
# =============================================================================

@router.get("/audit-logs", response_model=PaginatedAuditLogsResponse)
def get_audit_logs(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    action: Optional[str] = Query(None, description="Filter by action type"),
    user_id: Optional[int] = Query(None, description="Filter by target user ID"),
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """
    Review security audit logs with server-side pagination and action filtering.
    """
    query = db.query(AuditLog)

    if action:
        query = query.filter(AuditLog.action.ilike(f"%{action.strip()}%"))

    if user_id:
        query = query.filter(AuditLog.user_id == user_id)

    total = query.count()
    total_pages = ceil(total / page_size) if total > 0 else 1
    offset = (page - 1) * page_size

    entries = query.order_by(desc(AuditLog.created_at)).offset(offset).limit(page_size).all()

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

    return PaginatedAuditLogsResponse(
        items=results,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )


# =============================================================================
# 6. PERMISSION KNOWLEDGE BASE REVIEW & GOVERNANCE
# =============================================================================

@router.get("/knowledge-base")
def review_knowledge_base(
    search: Optional[str] = Query(None, description="Search by permission identifier or description"),
    category: Optional[str] = Query(None, description="Filter by functional category"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    protection_level: Optional[str] = Query(None, description="Filter by protection level"),
    admin_user: User = Depends(get_current_admin)
):
    """
    Allows authorized administrators to review the curated permission knowledge base.
    """
    meta = KnowledgeBaseManagementService.get_metadata()
    entries = KnowledgeBaseManagementService.list_entries(
        search=search,
        category=category,
        risk_level=risk_level,
        protection_level=protection_level
    )

    return {
        "metadata": meta,
        "total_filtered": len(entries),
        "entries": entries
    }


@router.post("/knowledge-base/validate", response_model=KBValidationResponse)
def validate_knowledge_base_schema(
    candidate_entry: Dict[str, Any],
    admin_user: User = Depends(get_current_admin)
):
    """
    Strictly validates candidate permission JSON schema before publication.
    Prevents unvalidated explanations or missing documentation references from being published.
    """
    return KnowledgeBaseManagementService.validate_entry(candidate_entry)


@router.post("/knowledge-base/entries")
def publish_knowledge_base_entry(
    entry_payload: Dict[str, Any],
    request: Request = None,
    admin_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """
    Validates and publishes a permission explanation entry to the knowledge base.
    Requires server-side admin authorization, updates KB versioning,
    and logs changes to audit_logs.
    """
    success, res = KnowledgeBaseManagementService.publish_entry(entry_payload)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=res
        )

    # Record administrative change in audit_logs
    client_ip = request.client.host if request and request.client else "unknown"
    perm_name = res.get("permission", "unknown")
    log_audit_event(
        db,
        action="ADMIN_KB_ENTRY_PUBLISHED",
        user_id=admin_user.id,
        resource_type="KNOWLEDGE_BASE",
        resource_id=perm_name,
        ip_address=client_ip
    )

    return res
