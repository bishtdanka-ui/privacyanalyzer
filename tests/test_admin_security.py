import pytest
from datetime import datetime, timezone
from fastapi import HTTPException

from backend.models.user import User
from backend.models.analysis import Analysis
from backend.models.permission import Permission
from backend.models.audit_log import AuditLog
from backend.schemas.admin import AdminUserUpdate
from backend.security.dependencies import get_current_admin, get_current_active_user
from backend.services.audit_service import log_audit_event
from backend.routers.admin import (
    get_system_stats,
    get_system_health,
    get_all_users,
    update_user_status,
    monitor_all_analyses,
    get_audit_logs,
    review_knowledge_base,
    validate_knowledge_base_schema,
    publish_knowledge_base_entry
)
from knowledge_base.lookup_service import permission_lookup_service


def test_admin_role_enforcement_rejects_ordinary_user(normal_user):
    """
    Validates that ordinary non-admin users are strictly rejected with 403 Forbidden
    at the server-side dependency level on all administrative routes.
    """
    with pytest.raises(HTTPException) as exc:
        get_current_admin(normal_user)
    assert exc.value.status_code == 403
    assert "Administrator privileges required" in exc.value.detail


def test_admin_system_stats_and_health_telemetry(admin_user, normal_user, db_session):
    """
    Validates administrative telemetry: total/active users, analysis statistics,
    permission detection statistics, unknown permission tracking, and application health.
    """
    # Create sample analysis with permissions
    analysis = Analysis(
        user_id=normal_user.id,
        app_name="Telemetry Test App",
        package_name="com.security.telemetry",
        total_permissions=3,
        dangerous_count=1,
        normal_count=1,
        special_count=0,
        risk_score=65.0,
        risk_level="HIGH"
    )
    db_session.add(analysis)
    db_session.flush()

    p_dang = Permission(
        analysis_id=analysis.id,
        name="android.permission.RECORD_AUDIO",
        short_name="RECORD_AUDIO",
        protection_level="dangerous",
        severity_score=8.0
    )
    p_norm = Permission(
        analysis_id=analysis.id,
        name="android.permission.INTERNET",
        short_name="INTERNET",
        protection_level="normal",
        severity_score=2.0
    )
    p_unk = Permission(
        analysis_id=analysis.id,
        name="com.oem.telemetry.DIAGNOSTICS",
        short_name="DIAGNOSTICS",
        protection_level="unknown",
        severity_score=4.0
    )
    db_session.add_all([p_dang, p_norm, p_unk])
    db_session.commit()

    # 1. System Stats
    stats = get_system_stats(admin_user=admin_user, db=db_session)
    assert stats["total_users"] >= 2
    assert stats["active_users"] >= 2
    assert stats["total_analyses"] >= 1
    assert stats["high_risk_count"] >= 1
    assert stats["average_risk_score"] > 0

    perm_stats = stats["permission_statistics"]
    assert perm_stats["total_permissions_detected"] >= 3
    assert perm_stats["dangerous_count"] >= 1
    assert perm_stats["normal_count"] >= 1
    assert perm_stats["unknown_count"] >= 1
    assert any(p["short_name"] == "RECORD_AUDIO" for p in perm_stats["top_detected_permissions"])
    assert any("DIAGNOSTICS" in p["permission"] for p in perm_stats["top_unknown_permissions"])

    # 2. System Health
    health = get_system_health(admin_user=admin_user, db=db_session)
    assert health.status in ("OPERATIONAL", "DEGRADED")
    assert health.database["status"] == "CONNECTED"
    assert health.knowledge_base["status"] == "LOADED"
    assert health.knowledge_base["entries_count"] >= 36
    assert health.security["password_hasher"] == "Argon2id"


def test_admin_user_management_and_activation_controls(admin_user, normal_user, db_session):
    """
    Validates paginated user retrieval, account deactivation/activation,
    safety guards against admin self-deactivation/self-demotion, and audit logging.
    """
    # 1. Paginated User Listing
    user_list = get_all_users(page=1, page_size=10, search=None, role=None, is_active=None, admin_user=admin_user, db=db_session)
    assert user_list.total >= 2
    assert any(u.email == normal_user.email for u in user_list.items)
    # Ensure no password hashes or tokens exposed
    user_dict = user_list.items[0].model_dump()
    assert "password_hash" not in user_dict
    assert "refresh_token" not in user_dict

    # 2. Deactivate normal_user
    req_deact = AdminUserUpdate(is_active=False)
    updated = update_user_status(user_id=normal_user.id, req=req_deact, request=None, admin_user=admin_user, db=db_session)
    assert updated.is_active is False

    # Verify deactivated user cannot access active endpoints
    db_session.refresh(normal_user)
    with pytest.raises(HTTPException) as exc_deact:
        get_current_active_user(normal_user)
    assert exc_deact.value.status_code == 403
    assert "deactivated" in exc_deact.value.detail.lower()

    # 3. Reactivate normal_user
    req_act = AdminUserUpdate(is_active=True)
    reactivated = update_user_status(user_id=normal_user.id, req=req_act, request=None, admin_user=admin_user, db=db_session)
    assert reactivated.is_active is True

    # 4. Safety Guard: Admin cannot deactivate their own account
    req_self_deact = AdminUserUpdate(is_active=False)
    with pytest.raises(HTTPException) as exc_self:
        update_user_status(user_id=admin_user.id, req=req_self_deact, request=None, admin_user=admin_user, db=db_session)
    assert exc_self.value.status_code == 400
    assert "cannot deactivate their own account" in exc_self.value.detail

    # 5. Safety Guard: Admin cannot demote themselves from admin role
    req_self_demote = AdminUserUpdate(role="user")
    with pytest.raises(HTTPException) as exc_demote:
        update_user_status(user_id=admin_user.id, req=req_self_demote, request=None, admin_user=admin_user, db=db_session)
    assert exc_demote.value.status_code == 400
    assert "cannot revoke their own administrative role" in exc_demote.value.detail

    # 6. Verify audit logs recorded the actions
    audit_events = db_session.query(AuditLog).filter(
        AuditLog.resource_id == str(normal_user.id)
    ).all()
    actions = {a.action for a in audit_events}
    assert "ADMIN_DEACTIVATE_USER" in actions
    assert "ADMIN_ACTIVATE_USER" in actions


def test_admin_analysis_monitoring_and_audit_trail(admin_user, normal_user, db_session):
    """
    Validates cross-platform analysis monitoring and paginated audit log review.
    """
    # 1. Create sample analysis & log audit event
    sample_analysis = Analysis(
        user_id=normal_user.id,
        app_name="Test Monitor App",
        package_name="com.test.monitor",
        total_permissions=2,
        dangerous_count=1,
        risk_score=50.0,
        risk_level="MEDIUM"
    )
    db_session.add(sample_analysis)

    log_audit_event(
        db_session,
        action="TEST_ADMIN_AUDIT_ACTION",
        user_id=admin_user.id,
        resource_type="SYSTEM",
        resource_id="1",
        ip_address="127.0.0.1"
    )

    # 2. Analysis Monitoring
    analyses_resp = monitor_all_analyses(page=1, page_size=10, search=None, risk_level=None, admin_user=admin_user, db=db_session)
    assert analyses_resp.total >= 1
    assert any(a.package_name == "com.test.monitor" for a in analyses_resp.items)

    # 3. Audit Trail
    audit_resp = get_audit_logs(page=1, page_size=20, action=None, user_id=None, admin_user=admin_user, db=db_session)
    assert audit_resp.total >= 1
    assert len(audit_resp.items) >= 1
    first_log = audit_resp.items[0]
    assert first_log.action is not None
    assert first_log.created_at is not None


def test_permission_knowledge_base_schema_validation_and_publishing(admin_user, db_session):
    """
    Validates permission knowledge base governance:
    - Reviewing knowledge base catalog & metadata.
    - Strict schema validation rejecting incomplete or invalid explanations.
    - Guard against publishing unvalidated entries.
    - Publishing vetted permission explanation with source documentation references.
    """
    # 1. Review Knowledge Base Catalog
    kb_review = review_knowledge_base(search=None, category=None, risk_level=None, protection_level=None, admin_user=admin_user)
    assert "metadata" in kb_review
    assert kb_review["metadata"]["total_entries"] >= 36
    assert len(kb_review["entries"]) >= 36

    # 2. Schema Validation: Invalid Entry (Missing required documentation_url & invalid protection level)
    invalid_candidate = {
        "permission": "android.permission.TEST_INVALID",
        "category": "Test",
        "display_name": "Test",
        "description": "Too short",
        "privacy_implications": [],
        "sensitive_data": [],
        "protection_level": "super_danger",  # Invalid
        "platform_context": "Short",
        "documentation_url": "ftp://bad-url",  # Invalid URL
        "risk_level": "EXTREME",  # Invalid
        "explanation": "Short"
    }
    val_invalid = validate_knowledge_base_schema(candidate_entry=invalid_candidate, admin_user=admin_user)
    assert val_invalid.valid is False
    assert len(val_invalid.errors) > 0

    # Attempting to publish invalid entry raises 422 Unprocessable Entity
    with pytest.raises(HTTPException) as exc_pub_invalid:
        publish_knowledge_base_entry(entry_payload=invalid_candidate, request=None, admin_user=admin_user, db=db_session)
    assert exc_pub_invalid.value.status_code == 422

    # 3. Schema Validation: Valid Entry
    valid_candidate = {
        "permission": "android.permission.NEARBY_WIFI_DEVICES",
        "category": "Network",
        "display_name": "Nearby Wi-Fi Devices Access",
        "description": "Allows an application to discover and connect to nearby Wi-Fi devices without deriving physical geographic location.",
        "privacy_implications": [
            "Allows communicating with peer devices over local Wi-Fi networks.",
            "May disclose Wi-Fi SSID names and BSSID hardware identifiers."
        ],
        "sensitive_data": [
            "Wi-Fi SSID Names",
            "BSSID Hardware MACs",
            "Peer Device Identifiers"
        ],
        "protection_level": "dangerous",
        "platform_context": "Introduced in Android 13 (API level 33). Decouples Wi-Fi device scanning from geographic location permission when neverForLocation flag is used.",
        "documentation_url": "https://developer.android.com/reference/android/Manifest.permission#NEARBY_WIFI_DEVICES",
        "risk_level": "MEDIUM",
        "explanation": "This application declares nearby Wi-Fi device access. This declaration does not prove that local device scanning has been executed."
    }

    val_valid = validate_knowledge_base_schema(candidate_entry=valid_candidate, admin_user=admin_user)
    assert val_valid.valid is True
    assert val_valid.permission == "android.permission.NEARBY_WIFI_DEVICES"

    # 4. Publish Vetted Entry
    pub_res = publish_knowledge_base_entry(entry_payload=valid_candidate, request=None, admin_user=admin_user, db=db_session)
    assert pub_res["permission"] == "android.permission.NEARBY_WIFI_DEVICES"
    assert "kb_version" in pub_res

    # 5. Verify Lookup Service immediately reflects the new entry
    lookup_res = permission_lookup_service.lookup("android.permission.NEARBY_WIFI_DEVICES")
    assert lookup_res["is_known"] is True
    assert lookup_res["category"] == "Network"
    assert lookup_res["documentation_url"].startswith("https://")

    # 6. Verify audit log recorded the KB update
    kb_audit = db_session.query(AuditLog).filter(
        AuditLog.action == "ADMIN_KB_ENTRY_PUBLISHED",
        AuditLog.resource_id == "android.permission.NEARBY_WIFI_DEVICES"
    ).first()
    assert kb_audit is not None
    assert kb_audit.user_id == admin_user.id
