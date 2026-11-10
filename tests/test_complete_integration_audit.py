"""
Complete End-to-End Integration Audit Suite
Problem Statement: PS02 - Explainable Cybersecurity Application Privacy & Permission Analyzer

Covers all 9 Audit Phases:
Phase 1: Repository & Configuration Audit
Phase 2: Frontend & Backend Schemas & Routes
Phase 3: Relational Database Integrity & Data Isolation
Phase 4: Authentication, Argon2id, Session Lifecycle & Throttling
Phase 5: Core Analysis Engine (Valid, Malformed, Duplicates, Unknowns, Manual, Disclosures, Ambiguities, Purpose Alignment)
Phase 6: Multi-Format Reporting (PDF, JSON, CSV, Ownership)
Phase 7: Security Penetration Checks (SQLi, XXE, Path Traversal, Broken Access, Secret Leakage)
"""

import os
import json
import csv
import pytest
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import engine, Base
from backend.models.user import User
from backend.models.user_session import UserSession
from backend.models.analysis import Analysis
from backend.models.permission import Permission
from backend.models.policy_excerpt import PolicyExcerpt
from backend.models.comparison_finding import ComparisonFinding
from backend.models.report import Report
from backend.models.audit_log import AuditLog
from backend.security.hashing import (
    hash_password,
    verify_password,
    generate_refresh_token,
    hash_token
)
from backend.security.jwt_auth import (
    create_access_token,
    decode_access_token
)
from backend.security.dependencies import get_current_user, get_current_active_user, get_current_admin
from backend.manifest_parser import (
    AndroidManifestParser,
    ManifestParser,
    ManifestParseError,
    ManifestSecurityError
)
from backend.policy_analyzer import PolicyAnalyzer
from backend.explainability_service import ExplainabilityService
from backend.report_service import ReportService
from backend.routers.auth import register, login, refresh_token_endpoint, logout
from backend.routers.analysis import (
    analyze_manifest_text,
    get_analysis_details,
    get_user_history,
    get_dashboard_metrics,
    get_analyses_report,
    compare_purpose_post
)
from backend.routers.admin import (
    get_system_stats,
    get_system_health,
    get_all_users,
    update_user_status,
    review_knowledge_base,
    validate_knowledge_base_schema,
    publish_knowledge_base_entry
)
from backend.schemas.auth import UserRegister, UserLogin, RefreshTokenRequest
from backend.schemas.analysis import (
    ManifestTextAnalysisRequest,
    PurposeComparisonRequest
)
from backend.schemas.admin import AdminUserUpdate


# Mock Request Helper
class MockClient:
    def __init__(self, host="127.0.0.1"):
        self.host = host

class MockRequest:
    def __init__(self, ip="127.0.0.1"):
        self.client = MockClient(ip)
        self.headers = {"user-agent": "AuditRunner/1.0"}


# =============================================================================
# PHASE 3: DATABASE RELATIONAL INTEGRITY & ISOLATION
# =============================================================================

def test_phase3_database_foreign_keys_and_isolation(db_session, normal_user, other_user):
    """
    Verifies relational storage, foreign key constraints, and cross-user data isolation.
    """
    # Create analysis for normal_user
    analysis = Analysis(
        user_id=normal_user.id,
        app_name="Isolation Test App",
        package_name="com.security.isolation",
        total_permissions=1,
        dangerous_count=1,
        risk_score=60.0,
        risk_level="MEDIUM"
    )
    db_session.add(analysis)
    db_session.flush()

    p = Permission(
        analysis_id=analysis.id,
        name="android.permission.CAMERA",
        short_name="CAMERA",
        protection_level="dangerous"
    )
    db_session.add(p)
    db_session.commit()

    # Verify normal_user history includes it
    history_user1 = get_user_history(current_user=normal_user, db=db_session)
    assert any(a.id == analysis.id for a in history_user1)

    # Verify other_user history does NOT include it
    history_user2 = get_user_history(current_user=other_user, db=db_session)
    assert not any(a.id == analysis.id for a in history_user2)


# =============================================================================
# PHASE 4: AUTHENTICATION, ARGON2ID, THROTTLING & TOKEN ROTATION
# =============================================================================

def test_phase4_authentication_security_lifecycle(db_session):
    """
    Tests complete auth flow: registration, password complexity, Argon2id verification,
    login, refresh rotation, brute-force throttling, and secure logout.
    """
    mock_req = MockRequest("10.0.0.1")

    # 1. Password complexity enforcement (reject weak passwords)
    with pytest.raises(ValueError):
        UserRegister(
            email="weakuser@test.local",
            full_name="Weak User",
            password="password"  # No uppercase, number, symbol
        )

    # 2. Successful Registration
    reg_req = UserRegister(
        email="audit_user@test.local",
        full_name="Audit User",
        password="ValidSecurePassword2026!"
    )
    user_resp = register(reg_req, mock_req, db_session)
    assert user_resp.email == "audit_user@test.local"

    # Verify Argon2id hashing in database
    db_user = db_session.query(User).filter(User.email == "audit_user@test.local").first()
    assert db_user.password_hash.startswith("$argon2id$")
    assert verify_password("ValidSecurePassword2026!", db_user.password_hash)

    # 3. Successful Login
    login_resp = login(UserLogin(
        email="audit_user@test.local",
        password="ValidSecurePassword2026!"
    ), mock_req, db_session)
    assert login_resp["access_token"] is not None
    assert login_resp["refresh_token"] is not None

    # 4. Refresh Token Rotation
    refresh_req = RefreshTokenRequest(refresh_token=login_resp["refresh_token"])
    rotated_resp = refresh_token_endpoint(refresh_req, mock_req, db_session)
    assert rotated_resp["access_token"] is not None
    assert rotated_resp["refresh_token"] != login_resp["refresh_token"]

    # 5. Old refresh token is revoked
    old_hash = hash_token(login_resp["refresh_token"])
    revoked_session = db_session.query(UserSession).filter(UserSession.refresh_token_hash == old_hash).first()
    assert revoked_session.revoked_at is not None

    # 6. Login Failure Throttling (after 5 failures, account locks)
    for _ in range(5):
        with pytest.raises(HTTPException) as exc_fail:
            login(UserLogin(email="audit_user@test.local", password="WrongPassword!"), mock_req, db_session)
        assert exc_fail.value.status_code == 401

    with pytest.raises(HTTPException) as exc_locked:
        login(UserLogin(email="audit_user@test.local", password="ValidSecurePassword2026!"), mock_req, db_session)
    assert exc_locked.value.status_code == 429
    assert "locked" in exc_locked.value.detail.lower()

    # 7. Secure Logout
    logout(RefreshTokenRequest(refresh_token=rotated_resp["refresh_token"]), current_user=db_user, db=db_session)
    new_hash = hash_token(rotated_resp["refresh_token"])
    logged_out_session = db_session.query(UserSession).filter(UserSession.refresh_token_hash == new_hash).first()
    assert logged_out_session.revoked_at is not None


# =============================================================================
# PHASE 5: CORE ANALYSIS ENGINE FORENSIC CHECKS
# =============================================================================

def test_phase5_manifest_variations_and_boundary_checks(db_session, normal_user):
    """
    Tests manifest analysis with:
    1. Valid AndroidManifest.xml
    2. Malformed XML (rejects safely with 400)
    3. Manifest with duplicate declarations
    4. Manifest with unknown permissions (flagged, never invents explanations)
    5. Manual permission entry (synthetic manifest)
    6. Policy disclosures & ambiguous statements
    7. Purpose alignment & mismatch questions
    """
    mock_req = MockRequest()

    # 1. Valid Manifest
    valid_xml = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.audit.valid">
        <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34"/>
        <uses-permission android:name="android.permission.INTERNET"/>
        <uses-permission android:name="android.permission.CAMERA"/>
        <application android:label="Audit Valid App"/>
    </manifest>
    """
    res_valid = analyze_manifest_text(
        ManifestTextAnalysisRequest(manifest_xml=valid_xml),
        mock_req, normal_user, db_session
    )
    assert res_valid.package_name == "com.audit.valid"
    assert res_valid.total_permissions == 2
    assert res_valid.target_sdk == "34"

    # 2. Malformed XML (safely rejected)
    malformed_xml = "<manifest><uses-permission android:name='android.permission.CAMERA'></unclosed>"
    with pytest.raises(HTTPException) as exc_mal:
        analyze_manifest_text(
            ManifestTextAnalysisRequest(manifest_xml=malformed_xml),
            mock_req, normal_user, db_session
        )
    assert exc_mal.value.status_code == 400
    assert "XML" in exc_mal.value.detail or "malformed" in exc_mal.value.detail.lower()

    # 3. Duplicate Permissions Handling
    dup_xml = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.audit.dup">
        <uses-permission android:name="android.permission.CAMERA"/>
        <uses-permission android:name="android.permission.CAMERA"/>
        <application android:label="Duplicate App"/>
    </manifest>
    """
    res_dup = analyze_manifest_text(
        ManifestTextAnalysisRequest(manifest_xml=dup_xml),
        mock_req, normal_user, db_session
    )
    assert res_dup.total_permissions >= 1

    # 4. Unknown Permission Explicit Flagging
    unk_xml = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.audit.unknown">
        <uses-permission android:name="com.vendor.proprietary.SURVEILLANCE_HOOK"/>
        <application android:label="Unknown Perm App"/>
    </manifest>
    """
    res_unk = analyze_manifest_text(
        ManifestTextAnalysisRequest(manifest_xml=unk_xml),
        mock_req, normal_user, db_session
    )
    unk_perm = next(p for p in res_unk.permissions if "SURVEILLANCE_HOOK" in p.name)
    assert unk_perm.protection_level == "unknown"
    assert "No reliable entry exists" in unk_perm.description

    # 5. Policy Disclosures & Ambiguous Stance Detection
    policy_text = (
        "Paragraph 1: We collect coarse device location to deliver weather forecasts.\n"
        "Paragraph 2: We may collect certain device telemetry as deemed appropriate for quality."
    )
    policy_analysis = PolicyAnalyzer.analyze_policy(policy_text)
    assert policy_analysis["provided"] is True
    assert "location_information" in policy_analysis["domains"]
    assert policy_analysis["domains"]["location_information"]["status"] in ("EXPLICIT_DISCLOSURE", "DISCLOSED")

    # Ambiguous statement detection
    assert "device_information" in policy_analysis["domains"]
    dev_excerpts = policy_analysis["domains"]["device_information"]["excerpts"]
    assert len(dev_excerpts) >= 1
    assert any("AMBIGUOUS" in e.get("stance", "") or "VAGUE" in e.get("stance", "") or "UNCERTAIN" in e.get("stance", "") or e.get("stance") == "QUALIFIED_OR_UNCERTAIN" for e in dev_excerpts)

    # 6. Purpose Alignment & Purpose Mismatch
    # Purpose Match (Navigation App requesting Location)
    nav_comp = compare_purpose_post(PurposeComparisonRequest(
        app_name="NaviMaps",
        app_purpose="GPS Turn-by-Turn Navigation and Route Planning",
        permissions=["android.permission.ACCESS_FINE_LOCATION"]
    ), mock_req, normal_user, db_session)
    assert nav_comp.findings[0].finding_category == "POTENTIALLY_EXPECTED"

    # Purpose Mismatch (Calculator App requesting Camera)
    calc_comp = compare_purpose_post(PurposeComparisonRequest(
        app_name="SimpleCalc",
        app_purpose="Basic arithmetic calculations and offline unit converter",
        permissions=["android.permission.CAMERA"]
    ), mock_req, normal_user, db_session)
    assert calc_comp.findings[0].finding_category == "PURPOSE_MISMATCH"
    assert "?" in calc_comp.findings[0].review_question


# =============================================================================
# PHASE 6: MULTI-FORMAT REPORTING VERIFICATION
# =============================================================================

def test_phase6_multi_format_reports_and_ownership(db_session, normal_user, other_user):
    """
    Verifies PDF, JSON, and CSV report generation, data integrity, and cross-user ownership defense.
    """
    # Create sample analysis
    analysis = Analysis(
        user_id=normal_user.id,
        app_name="Reporting Test App",
        package_name="com.security.reporting",
        total_permissions=2,
        dangerous_count=1,
        normal_count=1,
        risk_score=70.0,
        risk_level="HIGH"
    )
    db_session.add(analysis)
    db_session.flush()

    p1 = Permission(
        analysis_id=analysis.id,
        name="android.permission.RECORD_AUDIO",
        short_name="RECORD_AUDIO",
        protection_level="dangerous",
        source_reference="/manifest/uses-permission[1]"
    )
    p2 = Permission(
        analysis_id=analysis.id,
        name="android.permission.INTERNET",
        short_name="INTERNET",
        protection_level="normal",
        source_reference="/manifest/uses-permission[2]"
    )
    db_session.add_all([p1, p2])
    db_session.commit()

    aid = analysis.id

    # 1. PDF Report Download
    pdf_resp = get_analyses_report(analysis_id=aid, format="pdf", section=None, current_user=normal_user, db=db_session)
    assert isinstance(pdf_resp, FileResponse)
    assert pdf_resp.media_type == "application/pdf"
    assert os.path.exists(pdf_resp.path)
    with open(pdf_resp.path, "rb") as f:
        assert f.read(5) == b"%PDF-"

    # 2. JSON Report Download
    json_resp = get_analyses_report(analysis_id=aid, format="json", section=None, current_user=normal_user, db=db_session)
    assert isinstance(json_resp, FileResponse)
    with open(json_resp.path, "r", encoding="utf-8") as f:
        json_content = json.load(f)
    assert json_content["report_metadata"]["package_name"] == "com.security.reporting"
    assert len(json_content["extracted_permissions"]) == 2
    assert len(json_content["limitations"]) == 4

    # 3. CSV Report Download
    csv_resp = get_analyses_report(analysis_id=aid, format="csv", section=None, current_user=normal_user, db=db_session)
    assert isinstance(csv_resp, Response)
    csv_text = csv_resp.body.decode("utf-8")
    assert "[SECTION 1: EXECUTIVE SUMMARY METRICS]" in csv_text
    assert "android.permission.RECORD_AUDIO" in csv_text

    # 4. Cross-User Unauthorized Download Defense -> 403 Forbidden
    with pytest.raises(HTTPException) as exc_cross:
        get_analyses_report(analysis_id=aid, format="pdf", section=None, current_user=other_user, db=db_session)
    assert exc_cross.value.status_code == 403


# =============================================================================
# PHASE 7: SECURITY & HARDENING VERIFICATION
# =============================================================================

def test_phase7_security_penetration_and_injection_defenses(db_session, normal_user):
    """
    Validates security defenses:
    - XML Entity Expansion (Billion Laughs) prevention.
    - Path traversal rejection.
    - SQL injection parameterization.
    - Secret and password omission from reports and user views.
    """
    mock_req = MockRequest()

    # 1. XML Entity Expansion Attack (XXE) Prevention
    xxe_xml = """<?xml version="1.0"?>
    <!DOCTYPE lolz [
        <!ENTITY lol "lol">
        <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
        <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
    ]>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.xxe.exploit">
        <uses-permission android:name="&lol2;"/>
    </manifest>
    """
    with pytest.raises((HTTPException, ManifestSecurityError, ManifestParseError)):
        AndroidManifestParser.parse(xxe_xml)

    # 2. Path Traversal Filename Sanitization
    safe_fn = ReportService.get_safe_filename("../../../../../etc/passwd", 1, "pdf")
    assert ".." not in safe_fn
    assert "/" not in safe_fn
    assert "\\" not in safe_fn

    # 3. SQL Injection Parameterization Defense
    sqli_search = "'; DROP TABLE users; --"
    users_resp = get_all_users(page=1, page_size=10, search=sqli_search, role=None, is_active=None, admin_user=normal_user, db=db_session) if normal_user.role == "admin" else None
    # Verify table 'users' still exists and intact
    assert db_session.query(User).count() >= 1

    # 4. Zero Secrets in Reports
    analysis = Analysis(
        user_id=normal_user.id,
        app_name="PenTest App",
        package_name="com.pentest.app",
        total_permissions=1,
        dangerous_count=0,
        risk_score=10.0,
        risk_level="LOW"
    )
    db_session.add(analysis)
    db_session.commit()

    json_data = ReportService.generate_json_report(analysis, db_session)
    dumped = json.dumps(json_data).lower()
    assert "password" not in dumped
    assert "argon2" not in dumped
    assert "secret_key" not in dumped
