import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from fastapi import HTTPException

from backend.routers.auth import (
    register,
    login,
    refresh_token_endpoint,
    logout,
    get_profile,
    change_password
)
from backend.schemas.auth import (
    UserRegister,
    UserLogin,
    RefreshTokenRequest,
    PasswordChangeRequest
)
from backend.models.user_session import UserSession
from backend.security.hashing import hash_token
from backend.security.throttling import clear_login_failure

def make_mock_request(client_ip="127.0.0.1"):
    mock = MagicMock()
    mock.client.host = client_ip
    mock.headers = {"user-agent": "pytest-test-client"}
    return mock

def test_successful_registration(db_session):
    mock_req = make_mock_request()
    reg_payload = UserRegister(
        full_name="Alice Researcher",
        email="alice@company.org",
        password="ValidPassword123!",
        terms_accepted=True
    )
    user = register(reg_payload, mock_req, db_session)
    assert user.id is not None
    assert user.email == "alice@company.org"
    assert user.full_name == "Alice Researcher"
    assert user.role == "user"
    assert user.password_hash.startswith("$argon2id$")  # Verified Argon2id format!

def test_duplicate_email_rejection(db_session, normal_user):
    mock_req = make_mock_request()
    dup_payload = UserRegister(
        full_name="Impostor",
        email=normal_user.email,  # Duplicate
        password="ValidPassword123!",
        terms_accepted=True
    )
    with pytest.raises(HTTPException) as exc_info:
        register(dup_payload, mock_req, db_session)
    assert exc_info.value.status_code == 400
    assert "already exists" in exc_info.value.detail

def test_invalid_password_rejection():
    # 1. Too short
    with pytest.raises(ValueError):
        UserRegister(email="test@a.com", password="Sh1!", terms_accepted=True)
    # 2. Missing uppercase
    with pytest.raises(ValueError):
        UserRegister(email="test@a.com", password="nouppercase123!", terms_accepted=True)
    # 3. Missing digit
    with pytest.raises(ValueError):
        UserRegister(email="test@a.com", password="NoDigitsAtAll!", terms_accepted=True)
    # 4. Missing special character
    with pytest.raises(ValueError):
        UserRegister(email="test@a.com", password="NoSpecialChar123", terms_accepted=True)

def test_successful_login(db_session, normal_user):
    mock_req = make_mock_request()
    clear_login_failure(normal_user.email)
    
    login_payload = UserLogin(
        email=normal_user.email,
        password="AnalystPassword123!",
        remember_me=True
    )
    resp = login(login_payload, mock_req, db_session)
    assert "access_token" in resp
    assert "refresh_token" in resp
    assert resp["token_type"] == "bearer"
    assert resp["user"].email == normal_user.email

    # Verify session was created in database
    token_hash = hash_token(resp["refresh_token"])
    session = db_session.query(UserSession).filter(UserSession.refresh_token_hash == token_hash).first()
    assert session is not None
    assert session.user_id == normal_user.id
    assert session.is_active is True

def test_invalid_login(db_session, normal_user):
    mock_req = make_mock_request()
    clear_login_failure(normal_user.email)
    
    # Non-existent email
    with pytest.raises(HTTPException) as exc_info:
        login(UserLogin(email="nonexistent@example.com", password="Password123!"), mock_req, db_session)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid email or password."

    # Wrong password for existing user
    with pytest.raises(HTTPException) as exc_info2:
        login(UserLogin(email=normal_user.email, password="WrongPassword999!"), mock_req, db_session)
    assert exc_info2.value.status_code == 401
    assert exc_info2.value.detail == "Invalid email or password."

def test_login_throttling_after_repeated_failures(db_session, normal_user):
    mock_req = make_mock_request()
    clear_login_failure("throttled@example.com")
    
    bad_login = UserLogin(email="throttled@example.com", password="WrongPassword999!")
    
    # 5 failed attempts
    for _ in range(5):
        try:
            login(bad_login, mock_req, db_session)
        except HTTPException:
            pass

    # 6th attempt must be throttled with 429 Too Many Requests
    with pytest.raises(HTTPException) as exc_info:
        login(bad_login, mock_req, db_session)
    assert exc_info.value.status_code == 429
    assert "Too many failed login attempts" in exc_info.value.detail
    clear_login_failure("throttled@example.com")

def test_logout_and_token_revocation(db_session, normal_user):
    mock_req = make_mock_request()
    clear_login_failure(normal_user.email)
    
    login_resp = login(UserLogin(email=normal_user.email, password="AnalystPassword123!"), mock_req, db_session)
    raw_refresh = login_resp["refresh_token"]

    # Logout with refresh token
    logout(RefreshTokenRequest(refresh_token=raw_refresh), normal_user, db_session)

    # Refresh attempt with revoked token must fail
    with pytest.raises(HTTPException) as exc_info:
        refresh_token_endpoint(RefreshTokenRequest(refresh_token=raw_refresh), mock_req, db_session)
    assert exc_info.value.status_code == 401
    assert "Revoked refresh token" in exc_info.value.detail

def test_refresh_token_rotation(db_session, normal_user):
    mock_req = make_mock_request()
    clear_login_failure(normal_user.email)

    login_resp = login(UserLogin(email=normal_user.email, password="AnalystPassword123!"), mock_req, db_session)
    old_refresh = login_resp["refresh_token"]

    # Perform refresh
    new_tokens = refresh_token_endpoint(RefreshTokenRequest(refresh_token=old_refresh), mock_req, db_session)
    assert "access_token" in new_tokens
    assert "refresh_token" in new_tokens
    assert new_tokens["refresh_token"] != old_refresh  # New rotated refresh token!

    # Old refresh token is now revoked
    with pytest.raises(HTTPException) as exc_info:
        refresh_token_endpoint(RefreshTokenRequest(refresh_token=old_refresh), mock_req, db_session)
    assert exc_info.value.status_code == 401

def test_expired_session(db_session, normal_user):
    mock_req = make_mock_request()
    # Create expired session in DB directly
    raw_token = "expired_test_token_1234567890"
    token_hash = hash_token(raw_token)
    past_time = datetime.now(timezone.utc) - timedelta(days=2)
    
    expired_session = UserSession(
        user_id=normal_user.id,
        refresh_token_hash=token_hash,
        expires_at=past_time,
        revoked_at=None
    )
    db_session.add(expired_session)
    db_session.commit()

    with pytest.raises(HTTPException) as exc_info:
        refresh_token_endpoint(RefreshTokenRequest(refresh_token=raw_token), mock_req, db_session)
    assert exc_info.value.status_code == 401
    assert "expired" in exc_info.value.detail
