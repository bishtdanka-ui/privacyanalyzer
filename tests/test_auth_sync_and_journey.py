"""
Authentication Synchronization & Complete User Journey Test Suite
Problem Statement: PS02 - Explainable Cybersecurity Application Privacy & Permission Analyzer

Tests Requirements:
1. FastAPI is the sole authority for authentication.
2. Streamlit never authenticates users independently.
3. Authenticated user context is stored safely in server-side Streamlit session (`st.session_state`).
4. Never puts passwords or refresh tokens in URLs.
5. Never stores tokens in browser localStorage.
6. Short-lived access tokens and refresh-token rotation.
7. Refresh-token hashes stored in database (`user_sessions.refresh_token_hash`).
8. Session expiration and logout revocation handled cleanly.
9. All protected API calls require verified authentication.
10. Active session is revoked upon logout.
11. Dashboard pages are inaccessible without authentication.
12. User identity is fetched from authenticated backend response.
13. Frontend form `user_id` is never trusted.
14. Each database query is scoped to the authenticated user.
15. Complete user journey:
    Register → Login → Dashboard → New Analysis → Save Analysis → History → Logout.
16. Direct API requests cannot bypass authentication.
"""

from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
import streamlit as st

from backend.models.user import User
from backend.models.user_session import UserSession
from backend.models.analysis import Analysis
from backend.models.permission import Permission
from backend.schemas.auth import UserRegister, UserLogin, RefreshTokenRequest
from backend.schemas.analysis import ManifestTextAnalysisRequest
from backend.routers.auth import register, login, refresh_token_endpoint, logout, get_profile
from backend.routers.analysis import (
    analyze_manifest_text,
    get_user_history,
    get_analysis_details,
    get_dashboard_metrics,
    delete_analysis_record
)
from backend.security.dependencies import (
    get_current_user,
    get_current_active_user,
    get_current_admin
)
from backend.security.jwt_auth import create_access_token, decode_access_token
from backend.security.hashing import hash_password, hash_token, verify_password
from frontend.auth_client import AuthClient, auth_client
from frontend.api_client import APIClient, api_client
from frontend.state import is_authenticated, is_admin, init_session_state


def make_mock_request(client_ip="127.0.0.1"):
    mock = MagicMock()
    mock.client.host = client_ip
    mock.headers = {"user-agent": "pytest-auth-sync"}
    return mock


SAMPLE_MANIFEST_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.privacyguard.journeytest"
    android:versionCode="1"
    android:versionName="1.0.0">
    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.INTERNET" />
    <application android:label="Journey App" android:allowBackup="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""


# =============================================================================
# 1. DIRECT API AUTHENTICATION BYPASS DEFENSE TESTS
# =============================================================================

def test_direct_api_requests_cannot_bypass_authentication(db_session):
    """
    Ensure all protected endpoints reject unauthenticated or forged requests with 401.
    """
    # 1. Missing credentials entirely
    with pytest.raises(HTTPException) as exc_missing:
        get_current_user(None, db_session)
    assert exc_missing.value.status_code == 401
    assert "token is required" in exc_missing.value.detail.lower()

    # 2. Forged / invalid JWT token
    fake_creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="forged.header.signature")
    with pytest.raises(HTTPException) as exc_forged:
        get_current_user(fake_creds, db_session)
    assert exc_forged.value.status_code == 401
    assert "invalid or expired" in exc_forged.value.detail.lower()

    # 3. Expired JWT token
    expired_token = create_access_token(
        data={"sub": "999", "role": "user", "email": "ghost@local"},
        expires_delta=timedelta(seconds=-10)
    )
    expired_creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=expired_token)
    with pytest.raises(HTTPException) as exc_exp:
        get_current_user(expired_creds, db_session)
    assert exc_exp.value.status_code == 401

    # 4. Token referencing non-existent user
    non_existent_token = create_access_token(
        data={"sub": "99999", "role": "user", "email": "nonexistent@local"}
    )
    ghost_creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=non_existent_token)
    with pytest.raises(HTTPException) as exc_ghost:
        get_current_user(ghost_creds, db_session)
    assert exc_ghost.value.status_code == 401
    assert "no longer exists" in exc_ghost.value.detail.lower()


def test_deactivated_user_blocked_from_protected_endpoints(db_session, normal_user):
    """
    Verify deactivated users receive 403 Forbidden on protected routes.
    """
    normal_user.is_active = False
    db_session.commit()

    token = create_access_token(data={"sub": str(normal_user.id), "role": normal_user.role, "email": normal_user.email})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    user = get_current_user(creds, db_session)
    with pytest.raises(HTTPException) as exc:
        get_current_active_user(user)
    assert exc.value.status_code == 403
    assert "deactivated" in exc.value.detail.lower()


# =============================================================================
# 2. SHORT-LIVED TOKENS, REFRESH-TOKEN ROTATION & HASH STORAGE
# =============================================================================

def test_refresh_token_rotation_and_hash_storage(db_session, normal_user):
    """
    Verify:
    1. Raw refresh token is never stored in DB (only SHA-256 hash).
    2. Refresh rotates the token (old session revoked, new session created).
    3. Reusing revoked refresh token triggers security alarm and revokes all sessions.
    """
    req = make_mock_request()

    # Login to issue tokens
    login_resp = login(
        UserLogin(email=normal_user.email, password="AnalystPassword123!"),
        request=req,
        db=db_session
    )
    raw_refresh_1 = login_resp["refresh_token"]
    hash_1 = hash_token(raw_refresh_1)

    # Verify session recorded with hash, not plaintext
    session_1 = db_session.query(UserSession).filter(UserSession.refresh_token_hash == hash_1).first()
    assert session_1 is not None
    assert session_1.user_id == normal_user.id
    assert session_1.revoked_at is None

    # Rotate refresh token
    rotate_resp = refresh_token_endpoint(
        RefreshTokenRequest(refresh_token=raw_refresh_1),
        request=req,
        db=db_session
    )
    raw_refresh_2 = rotate_resp["refresh_token"]
    assert raw_refresh_2 != raw_refresh_1

    # Verify old session is marked revoked
    db_session.refresh(session_1)
    assert session_1.revoked_at is not None

    # Verify new session exists
    hash_2 = hash_token(raw_refresh_2)
    session_2 = db_session.query(UserSession).filter(UserSession.refresh_token_hash == hash_2).first()
    assert session_2 is not None
    assert session_2.revoked_at is None

    # Reusing old revoked refresh token MUST be rejected
    with pytest.raises(HTTPException) as exc_reuse:
        refresh_token_endpoint(
            RefreshTokenRequest(refresh_token=raw_refresh_1),
            request=req,
            db=db_session
        )
    assert exc_reuse.value.status_code == 401
    assert "revoked" in exc_reuse.value.detail.lower()

    # Reuse attempt must terminate all sessions for this user
    db_session.refresh(session_2)
    assert session_2.revoked_at is not None


# =============================================================================
# 3. STREAMLIT SESSION STATE & AUTHORITATIVE CLIENT TESTS
# =============================================================================

def test_streamlit_session_state_and_auth_client_integration():
    """
    Verify AuthClient stores credentials in st.session_state server-side,
    never puts tokens in URLs, and cleans up on logout.
    """
    client = AuthClient(base_url="http://testbackend.local/api/v1")

    # Set up mock session_state
    init_session_state()
    assert not is_authenticated()
    assert not is_admin()

    # Mock login response
    mock_login_data = {
        "access_token": "mock.access.jwt",
        "refresh_token": "mock_refresh_token_secret_123",
        "token_type": "bearer",
        "expires_in": 1800,
        "user": {
            "id": 42,
            "email": "analyst@security.local",
            "full_name": "Test Analyst",
            "role": "user",
            "is_active": True
        }
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_login_data

    with patch("requests.post", return_value=mock_resp):
        success, data = client.login("analyst@security.local", "SuperSecretPassword123!")
        assert success is True
        assert is_authenticated() is True
        assert is_admin() is False
        assert client.get_token() == "mock.access.jwt"
        assert client.get_refresh_token() == "mock_refresh_token_secret_123"
        user = client.get_current_user()
        assert user["id"] == 42
        assert user["email"] == "analyst@security.local"

    # Verify query parameters are empty (never leaking tokens into URL)
    query_params = getattr(st, "query_params", {})
    assert "token" not in query_params
    assert "password" not in query_params
    assert "refresh_token" not in query_params

    # Test Logout revokes session
    mock_logout_resp = MagicMock()
    mock_logout_resp.status_code = 200
    mock_logout_resp.json.return_value = {"message": "Logged out successfully."}

    with patch("requests.post", return_value=mock_logout_resp):
        client.logout()
        assert is_authenticated() is False
        assert client.get_token() is None
        assert client.get_refresh_token() is None
        assert client.get_current_user() is None


def test_api_client_automatic_refresh_on_401():
    """
    Verify APIClient automatically catches 401 responses, executes refresh-token
    rotation, and retries the request transparently.
    """
    init_session_state()
    st.session_state["token"] = "expired.jwt.token"
    st.session_state["refresh_token"] = "valid.refresh.token"
    st.session_state["user"] = {"id": 10, "email": "user@local", "role": "user"}

    test_api = APIClient(base_url="http://testbackend.local/api/v1")

    # First call returns 401 (expired)
    resp_401 = MagicMock()
    resp_401.status_code = 401

    # Second call (after rotation) returns 200
    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.json.return_value = {"total_analyses": 5}

    with patch("frontend.auth_client.auth_client.refresh_session", return_value=True) as mock_refresh:
        with patch.object(test_api, "_request", wraps=test_api._request) as mock_req:
            with patch("requests.request", side_effect=[resp_401, resp_200]):
                res = test_api._request("GET", "/analysis/dashboard/metrics", auto_refresh=True)
                assert res.status_code == 200
                assert mock_refresh.called


# =============================================================================
# 4. SCOPED USER QUERIES & DISREGARD OF FORM USER_ID
# =============================================================================

def test_user_id_from_frontend_ignored_and_queries_scoped(db_session, normal_user, other_user):
    """
    Verify:
    1. Analysis persistence always uses authenticated token user.id.
    2. Queries are strictly scoped to the authenticated user.
    3. User A cannot view or delete User B's records.
    """
    req = make_mock_request()

    # Analyze and save record for normal_user
    analysis_resp_user1 = analyze_manifest_text(
        req=ManifestTextAnalysisRequest(
            manifest_xml=SAMPLE_MANIFEST_XML,
            privacy_policy_text="We collect camera pictures for profiling."
        ),
        request=req,
        current_user=normal_user,
        db=db_session
    )
    user1_analysis_id = analysis_resp_user1.id

    # Verify record in DB belongs to normal_user.id
    saved = db_session.query(Analysis).filter(Analysis.id == user1_analysis_id).first()
    assert saved is not None
    assert saved.user_id == normal_user.id
    assert saved.user_id != other_user.id

    # other_user queries history: must NOT see normal_user's analysis
    other_history = get_user_history(current_user=other_user, db=db_session)
    assert not any(a.id == user1_analysis_id for a in other_history)

    # other_user attempts to retrieve normal_user's analysis details: 404
    with pytest.raises(HTTPException) as exc_detail:
        get_analysis_details(analysis_id=user1_analysis_id, current_user=other_user, db=db_session)
    assert exc_detail.value.status_code == 404

    # other_user attempts to delete normal_user's analysis: 404
    with pytest.raises(HTTPException) as exc_del:
        delete_analysis_record(analysis_id=user1_analysis_id, current_user=other_user, db=db_session)
    assert exc_del.value.status_code == 404


# =============================================================================
# 5. COMPLETE USER JOURNEY TEST:
# Register → Login → Dashboard → New Analysis → Save Analysis → History → Logout
# =============================================================================

def test_complete_user_journey(db_session):
    """
    End-to-end user lifecycle test:
    Register → Login → Dashboard → New Analysis → Save Analysis → History → Logout
    """
    req = make_mock_request()
    journey_email = "analyst.journey@privacyguard.local"
    journey_pass = "SecureJourneyPass2026!"
    journey_name = "Journey Analyst"

    # -------------------------------------------------------------------------
    # STEP 1: REGISTER
    # -------------------------------------------------------------------------
    reg_req = UserRegister(
        email=journey_email,
        full_name=journey_name,
        password=journey_pass,
        terms_accepted=True
    )
    registered_user = register(reg_req, request=req, db=db_session)
    assert registered_user.id is not None
    assert registered_user.email == journey_email
    assert registered_user.role == "user"
    assert verify_password(journey_pass, registered_user.password_hash)

    # Duplicate registration must fail
    with pytest.raises(HTTPException) as exc_dup:
        register(reg_req, request=req, db=db_session)
    assert exc_dup.value.status_code == 400

    # -------------------------------------------------------------------------
    # STEP 2: LOGIN
    # -------------------------------------------------------------------------
    login_req = UserLogin(email=journey_email, password=journey_pass, remember_me=False)
    login_resp = login(login_req, request=req, db=db_session)

    access_token = login_resp["access_token"]
    refresh_token = login_resp["refresh_token"]
    user_data = login_resp["user"]

    assert access_token is not None
    assert refresh_token is not None
    assert user_data.id == registered_user.id
    assert user_data.email == journey_email

    # Verify Bearer token decodes to user ID
    payload = decode_access_token(access_token)
    assert payload["sub"] == str(registered_user.id)
    assert payload["role"] == "user"

    # Authenticate dependency
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=access_token)
    authenticated_user = get_current_user(creds, db_session)
    active_user = get_current_active_user(authenticated_user)
    assert active_user.id == registered_user.id

    # -------------------------------------------------------------------------
    # STEP 3: DASHBOARD METRICS (Empty State)
    # -------------------------------------------------------------------------
    initial_metrics = get_dashboard_metrics(current_user=active_user, db=db_session)
    assert initial_metrics["total_analyses"] == 0
    assert initial_metrics["total_permissions"] == 0
    assert initial_metrics["high_risks"] == 0

    # -------------------------------------------------------------------------
    # STEP 4: NEW ANALYSIS & SAVE ANALYSIS
    # -------------------------------------------------------------------------
    analysis_input = ManifestTextAnalysisRequest(
        manifest_xml=SAMPLE_MANIFEST_XML,
        privacy_policy_text="We collect camera streams and user credentials for analysis."
    )
    analysis_result = analyze_manifest_text(
        req=analysis_input,
        request=req,
        current_user=active_user,
        db=db_session
    )

    analysis_id = analysis_result.id
    assert analysis_id is not None
    assert analysis_result.package_name == "com.privacyguard.journeytest"
    assert analysis_result.total_permissions == 2
    assert analysis_result.dangerous_count == 1  # CAMERA
    assert analysis_result.risk_level in ("HIGH", "MEDIUM", "LOW")

    # Verify persisted in database under authenticated user
    persisted = db_session.query(Analysis).filter(
        Analysis.id == analysis_id,
        Analysis.user_id == active_user.id
    ).first()
    assert persisted is not None
    assert persisted.package_name == "com.privacyguard.journeytest"
    assert len(persisted.permissions) == 2

    # -------------------------------------------------------------------------
    # STEP 5: DASHBOARD METRICS (Updated State)
    # -------------------------------------------------------------------------
    updated_metrics = get_dashboard_metrics(current_user=active_user, db=db_session)
    assert updated_metrics["total_analyses"] == 1
    assert updated_metrics["total_permissions"] == 2
    assert len(updated_metrics["recent_analyses"]) == 1
    assert updated_metrics["recent_analyses"][0]["id"] == analysis_id

    # -------------------------------------------------------------------------
    # STEP 6: HISTORY
    # -------------------------------------------------------------------------
    history_records = get_user_history(current_user=active_user, db=db_session)
    assert len(history_records) == 1
    assert history_records[0].id == analysis_id
    assert history_records[0].package_name == "com.privacyguard.journeytest"

    # Inspect details
    details = get_analysis_details(analysis_id=analysis_id, current_user=active_user, db=db_session)
    assert details.id == analysis_id
    assert len(details.permissions) == 2
    camera_perm = next(p for p in details.permissions if "CAMERA" in p.name)
    assert camera_perm.protection_level == "dangerous"

    # -------------------------------------------------------------------------
    # STEP 7: LOGOUT & SESSION REVOCATION
    # -------------------------------------------------------------------------
    logout_res = logout(
        req=RefreshTokenRequest(refresh_token=refresh_token),
        current_user=active_user,
        db=db_session
    )
    assert "Logged out successfully" in logout_res["message"]

    # Verify session is marked revoked in database
    ref_hash = hash_token(refresh_token)
    session_rec = db_session.query(UserSession).filter(UserSession.refresh_token_hash == ref_hash).first()
    assert session_rec is not None
    assert session_rec.revoked_at is not None

    # Attempting to refresh using the revoked session fails
    with pytest.raises(HTTPException) as exc_ref:
        refresh_token_endpoint(
            RefreshTokenRequest(refresh_token=refresh_token),
            request=req,
            db=db_session
        )
    assert exc_ref.value.status_code == 401


# =============================================================================
# 6. SYNTHETIC DEMO DATA INTEGRITY TEST
# =============================================================================

def test_synthetic_demo_data_integrity():
    """
    Verify that all synthetic demonstration data files are present, well-formed,
    and validly parseable by AndroidManifestParser and PolicyAnalyzer.
    """
    from pathlib import Path
    from backend.manifest_parser import AndroidManifestParser
    from backend.policy_analyzer import PolicyAnalyzer

    base_dir = Path(__file__).resolve().parent.parent
    demo_dir = base_dir / "data" / "synthetic_demo"

    # 1. Sample standalone manifest and policy
    sample_manifest = demo_dir / "sample_manifest.xml"
    sample_policy = demo_dir / "sample_privacy_policy.txt"
    assert sample_manifest.exists()
    assert sample_policy.exists()

    parsed_sample = AndroidManifestParser.parse(sample_manifest.read_text(encoding="utf-8"))
    assert parsed_sample["package_name"] == "com.privacyguard.demo.quickscan"
    assert "android.permission.CAMERA" in [p["permission_name"] for p in parsed_sample["permission_records"]]
    # Has unknown custom telemetry
    assert any("DIAGNOSTIC_TELEMETRY" in p["permission_name"] for p in parsed_sample["permission_records"])

    policy_sample = PolicyAnalyzer.analyze_policy(sample_policy.read_text(encoding="utf-8"), app_name="QuickScan")
    assert policy_sample["word_count"] > 20
    assert "camera_microphone" in policy_sample["domains"]
    assert policy_sample["domains"]["camera_microphone"]["status"] == "EXPLICIT_DISCLOSURE"

    # 2. Calculator demo
    calc_manifest = demo_dir / "calculator" / "synthetic_calculator_manifest.xml"
    calc_policy = demo_dir / "calculator" / "synthetic_calculator_policy.txt"
    assert calc_manifest.exists() and calc_policy.exists()
    parsed_calc = AndroidManifestParser.parse(calc_manifest.read_text(encoding="utf-8"))
    assert parsed_calc["package_name"] == "com.privacyguard.demo.calculator"

    # 3. Navigation demo
    nav_manifest = demo_dir / "navigation" / "synthetic_navigation_manifest.xml"
    nav_policy = demo_dir / "navigation" / "synthetic_navigation_policy.txt"
    assert nav_manifest.exists() and nav_policy.exists()
    parsed_nav = AndroidManifestParser.parse(nav_manifest.read_text(encoding="utf-8"))
    assert parsed_nav["package_name"] == "com.privacyguard.demo.navigation"
    assert "android.permission.ACCESS_FINE_LOCATION" in [p["permission_name"] for p in parsed_nav["permission_records"]]

    # 4. Messaging demo
    msg_manifest = demo_dir / "messaging" / "synthetic_messaging_manifest.xml"
    msg_policy = demo_dir / "messaging" / "synthetic_messaging_policy.txt"
    assert msg_manifest.exists() and msg_policy.exists()
    parsed_msg = AndroidManifestParser.parse(msg_manifest.read_text(encoding="utf-8"))
    assert parsed_msg["package_name"] == "com.privacyguard.demo.pulsechat"
    assert "android.permission.READ_CONTACTS" in [p["permission_name"] for p in parsed_msg["permission_records"]]


