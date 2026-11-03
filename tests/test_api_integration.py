import os
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from fastapi import HTTPException

from backend.routers.analysis import (
    analyze_manifest_text,
    get_user_history,
    get_analysis_details,
    download_pdf_report,
    delete_analysis_record
)
from backend.routers.admin import (
    get_all_users,
    update_user_status,
    get_system_stats,
    get_audit_logs
)
from backend.routers.auth import (
    login,
    register,
    get_profile,
    update_profile,
    get_user_sessions,
    ProfileUpdateRequest
)
from backend.schemas.analysis import ManifestTextAnalysisRequest
from backend.schemas.admin import AdminUserUpdate
from backend.schemas.auth import UserLogin, UserRegister
from backend.models.analysis import Analysis
from backend.models.permission import Permission
from backend.models.comparison_finding import ComparisonFinding
from backend.models.report import Report
from backend.models.user_session import UserSession

BASE_DIR = Path(__file__).resolve().parent.parent

def make_mock_request(client_ip="127.0.0.1"):
    mock = MagicMock()
    mock.client.host = client_ip
    mock.headers = {"user-agent": "pytest-test-suite"}
    return mock

def test_database_and_api_connectivity(db_session):
    # Verify DB session can query tables
    assert db_session.is_active is True
    from backend.main import healthcheck
    health = healthcheck()
    assert health["status"] == "healthy"
    assert health["database"] == "connected"

def test_user_session_and_profile_flow(db_session):
    mock_req = make_mock_request()
    
    # Register
    reg_req = UserRegister(
        email="session_user@example.com",
        username="session_user",
        full_name="Original Name",
        password="Password123!"
    )
    user = register(reg_req, mock_req, db_session)
    assert user.id is not None

    # Login and verify session creation in user_sessions table
    login_resp = login(UserLogin(username_or_email="session_user", password="Password123!"), mock_req, db_session)
    assert login_resp["access_token"] is not None

    # Check user_sessions table
    sessions = get_user_sessions(user, db_session)
    assert len(sessions) >= 1
    assert sessions[0].is_active is True

    # Update profile
    prof_update = ProfileUpdateRequest(full_name="Updated Analyst Name")
    updated_user = update_profile(prof_update, user, db_session)
    assert updated_user.full_name == "Updated Analyst Name"

def test_full_analysis_workflow_and_relational_storage(db_session, normal_user):
    mock_req = make_mock_request()
    
    sample_path = BASE_DIR / "data" / "sample_manifests" / "sample_malicious_spyware.xml"
    with open(sample_path, "r", encoding="utf-8") as f:
        xml_text = f.read()

    req = ManifestTextAnalysisRequest(
        manifest_xml=xml_text,
        privacy_policy_text="We do not track location coordinates or read SMS."
    )

    # 1. Run Analysis and verify response
    analysis_resp = analyze_manifest_text(req, mock_req, normal_user, db_session)
    assert analysis_resp.package_name == "com.superboost.flashlight.free"
    assert analysis_resp.risk_level in ("HIGH", "CRITICAL")
    assert len(analysis_resp.combo_findings) > 0
    assert analysis_resp.id is not None
    record_id = analysis_resp.id

    # 2. Verify all normalized tables were populated
    analysis_in_db = db_session.query(Analysis).filter(Analysis.id == record_id).first()
    assert analysis_in_db is not None
    assert analysis_in_db.user_id == normal_user.id

    perms_in_db = db_session.query(Permission).filter(Permission.analysis_id == record_id).all()
    assert len(perms_in_db) > 0
    # Must have CAMERA, SMS, RECORD_AUDIO etc.
    perm_names = [p.name for p in perms_in_db]
    assert "android.permission.CAMERA" in perm_names
    assert "android.permission.READ_SMS" in perm_names

    findings_in_db = db_session.query(ComparisonFinding).filter(ComparisonFinding.analysis_id == record_id).all()
    assert len(findings_in_db) > 0
    finding_types = [f.finding_type for f in findings_in_db]
    assert "COMBO_THREAT" in finding_types

    reports_in_db = db_session.query(Report).filter(Report.analysis_id == record_id).all()
    assert len(reports_in_db) == 1
    assert reports_in_db[0].report_format == "PDF"
    assert os.path.exists(reports_in_db[0].file_path)

    # 3. Get User History
    history = get_user_history(normal_user, db_session)
    assert len(history) >= 1
    assert history[0].package_name == "com.superboost.flashlight.free"

    # 4. Get Analysis Details with reconstructed relations
    details = get_analysis_details(record_id, normal_user, db_session)
    assert details.id == record_id
    assert details.dangerous_count > 0
    assert len(details.permissions) == len(perms_in_db)
    assert len(details.combo_findings) > 0

    # 5. Download PDF
    file_resp = download_pdf_report(record_id, normal_user, db_session)
    assert os.path.exists(file_resp.path)
    assert file_resp.media_type == "application/pdf"
    assert os.path.getsize(file_resp.path) > 1000

    # 6. Delete Analysis Record and verify cascade
    del_res = delete_analysis_record(record_id, normal_user, db_session)
    assert "deleted" in del_res["message"]
    assert db_session.query(Analysis).filter(Analysis.id == record_id).first() is None
    assert db_session.query(Permission).filter(Permission.analysis_id == record_id).count() == 0

def test_admin_stats_and_user_management(db_session, admin_user, normal_user):
    mock_req = make_mock_request()
    
    # Get stats
    stats = get_system_stats(admin_user, db_session)
    assert stats["total_users"] >= 2
    assert "critical_risk_count" in stats

    # List users
    users = get_all_users(admin_user, db_session)
    assert len(users) >= 2

    # Toggle user active status
    patch_req = AdminUserUpdate(is_active=False)
    updated = update_user_status(normal_user.id, patch_req, admin_user, db_session)
    assert updated.is_active is False

    # Deactivated user cannot log in
    with pytest.raises(HTTPException) as exc_info:
        login(UserLogin(username_or_email=normal_user.username, password="AnalystPassword123!"), mock_req, db_session)
    assert exc_info.value.status_code == 403

    # Audit logs
    logs = get_audit_logs(50, admin_user, db_session)
    assert len(logs) >= 1
