import os
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

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
from backend.schemas.analysis import ManifestTextAnalysisRequest
from backend.schemas.admin import AdminUserUpdate
from backend.models.analysis import Analysis
from backend.models.permission import Permission
from backend.models.comparison_finding import ComparisonFinding
from backend.models.report import Report
from backend.security.dependencies import get_current_user, get_current_active_user, get_current_admin
from backend.security.jwt_auth import create_access_token

BASE_DIR = Path(__file__).resolve().parent.parent

def make_mock_request(client_ip="127.0.0.1"):
    mock = MagicMock()
    mock.client.host = client_ip
    mock.headers = {"user-agent": "pytest-integration-client"}
    return mock

def test_database_and_api_connectivity(db_session):
    assert db_session.is_active is True
    from backend.main import healthcheck
    health = healthcheck()
    assert health["status"] == "healthy"
    assert health["database"] == "connected"

def test_unauthorized_api_access(db_session):
    # 1. Missing credentials
    with pytest.raises(HTTPException) as exc1:
        get_current_user(None, db_session)
    assert exc1.value.status_code == 401

    # 2. Corrupt / fake token
    fake_creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="completely.fake.token")
    with pytest.raises(HTTPException) as exc2:
        get_current_user(fake_creds, db_session)
    assert exc2.value.status_code == 401

def test_admin_permission_enforcement(db_session, normal_user, admin_user):
    # Standard user attempting admin endpoint fails with 403 Forbidden
    with pytest.raises(HTTPException) as exc:
        get_current_admin(normal_user)
    assert exc.value.status_code == 403
    assert "Administrator privileges required" in exc.value.detail

    # Admin user succeeds
    admin = get_current_admin(admin_user)
    assert admin.role == "admin"

    # Admin stats can be retrieved by admin
    stats = get_system_stats(admin_user, db_session)
    assert "total_users" in stats

def test_cross_user_data_access_prevention(db_session, normal_user, other_user):
    mock_req = make_mock_request()
    sample_path = BASE_DIR / "data" / "sample_manifests" / "sample_safe_calculator.xml"
    with open(sample_path, "r", encoding="utf-8") as f:
        xml_text = f.read()

    req = ManifestTextAnalysisRequest(manifest_xml=xml_text)

    # normal_user runs an analysis
    analysis_resp = analyze_manifest_text(req, mock_req, normal_user, db_session)
    user_record_id = analysis_resp.id

    # other_user attempts to view normal_user's analysis record -> 404 Not Found
    with pytest.raises(HTTPException) as exc_detail:
        get_analysis_details(user_record_id, other_user, db_session)
    assert exc_detail.value.status_code == 404
    assert "not found" in exc_detail.value.detail

    # other_user attempts to download normal_user's PDF report -> 404 Not Found
    with pytest.raises(HTTPException) as exc_pdf:
        download_pdf_report(user_record_id, other_user, db_session)
    assert exc_pdf.value.status_code == 404

    # other_user attempts to delete normal_user's analysis record -> 404 Not Found
    with pytest.raises(HTTPException) as exc_del:
        delete_analysis_record(user_record_id, other_user, db_session)
    assert exc_del.value.status_code == 404

    # Record still exists and belongs to normal_user
    assert db_session.query(Analysis).filter(Analysis.id == user_record_id).first().user_id == normal_user.id

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
