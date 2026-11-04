from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from backend.models.audit_log import AuditLog

def log_audit_event(
    db: Session,
    action: str,
    user_id: Optional[int] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    ip_address: Optional[str] = None
) -> AuditLog:
    """
    Persist security and compliance audit events to the database.
    """
    entry = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        ip_address=ip_address
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
