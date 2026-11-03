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
from backend.schemas.analysis import ManifestTextAnalysisRequest
from backend.schemas.admin import AdminUserUpdate
from backend.schemas.auth import UserLogin
from backend.routers.auth import login

BASE_DIR = Path(__file__).resolve().parent.parent

def make_mock_request(client_ip="127.0.0.1"):
    mock = MagicMock()
    mock.client.host = client_ip
    return mock

def test_full_analysis_workflow_and_pdf(db_session, normal_user):
    mock_req = make_mock_request()
    
    sample_path = BASE_DIR / "data" / "sample_manifests" / "sample_malicious_spyware.xml"
    with open(sample_path, "r", encoding="utf-8") as f:
        xml_text = f.read()

    req = ManifestTextAnalysisRequest(
        manifest_xml=xml_text,
        privacy_policy_text="We do not track location coordinates or read SMS."
    )

    # 1. Run Analysis
    analysis_resp = analyze_manifest_text(req, mock_req, normal_user, db_session)
    assert analysis_resp.package_name == "com.superboost.flashlight.free"
    assert analysis_resp.risk_level in ("HIGH", "CRITICAL")
    assert len(analysis_resp.combo_findings) > 0
    assert analysis_resp.id is not None
    record_id = analysis_resp.id

    # 2. Get User History
    history = get_user_history(normal_user, db_session)
    assert len(history) >= 1
    assert history[0].package_name == "com.superboost.flashlight.free"

    # 3. Get Analysis Details
    details = get_analysis_details(record_id, normal_user, db_session)
    assert details.id == record_id
    assert details.dangerous_count > 0

    # 4. Download PDF
    file_resp = download_pdf_report(record_id, normal_user, db_session)
    assert os.path.exists(file_resp.path)
    assert file_resp.media_type == "application/pdf"
    assert os.path.getsize(file_resp.path) > 1000

    # 5. Delete Analysis Record
    del_res = delete_analysis_record(record_id, normal_user, db_session)
    assert "deleted" in del_res["message"]

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
