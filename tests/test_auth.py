import pytest
from unittest.mock import MagicMock
from fastapi import HTTPException
from backend.routers.auth import register, login, get_profile, change_password
from backend.schemas.auth import UserRegister, UserLogin, PasswordChangeRequest

def make_mock_request(client_ip="127.0.0.1"):
    mock = MagicMock()
    mock.client.host = client_ip
    return mock

def test_register_and_login_flow(db_session):
    mock_req = make_mock_request()
    
    reg_payload = UserRegister(
        email="alice@example.com",
        username="alice",
        full_name="Alice Tester",
        password="Password123!"
    )
    
    # Register
    user = register(reg_payload, mock_req, db_session)
    assert user.email == "alice@example.com"
    assert user.username == "alice"
    assert user.role == "user"

    # Duplicate registration fails
    with pytest.raises(HTTPException) as exc_info:
        register(reg_payload, mock_req, db_session)
    assert exc_info.value.status_code == 400

    # Login success
    login_payload = UserLogin(
        username_or_email="alice",
        password="Password123!"
    )
    token_resp = login(login_payload, mock_req, db_session)
    assert token_resp["token_type"] == "bearer"
    assert token_resp["access_token"] is not None

    # Get profile
    profile = get_profile(user)
    assert profile.username == "alice"

    # Change password
    change_req = PasswordChangeRequest(
        old_password="Password123!",
        new_password="NewSecurePassword456!"
    )
    res_change = change_password(change_req, user, db_session)
    assert "successfully" in res_change["message"]

    # Login with new password
    login_new = login(UserLogin(username_or_email="alice", password="NewSecurePassword456!"), mock_req, db_session)
    assert login_new["access_token"] is not None

def test_login_invalid_password(db_session, normal_user):
    mock_req = make_mock_request()
    login_payload = UserLogin(
        username_or_email=normal_user.username,
        password="WrongPassword!"
    )
    with pytest.raises(HTTPException) as exc_info:
        login(login_payload, mock_req, db_session)
    assert exc_info.value.status_code == 401
