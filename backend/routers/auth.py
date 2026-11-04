from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from backend.config import settings
from backend.database import get_db
from backend.models.user import User
from backend.models.user_session import UserSession
from backend.schemas.auth import (
    UserRegister,
    UserLogin,
    RefreshTokenRequest,
    TokenResponse,
    UserResponse,
    PasswordChangeRequest
)
from backend.security.hashing import (
    hash_password,
    verify_password,
    generate_refresh_token,
    hash_token
)
from backend.security.jwt_auth import create_access_token
from backend.security.throttling import (
    check_login_throttled,
    record_login_failure,
    clear_login_failure
)
from backend.security.dependencies import get_current_active_user
from backend.services.audit_service import log_audit_event

router = APIRouter(prefix="/auth", tags=["Authentication"])

class ProfileUpdateRequest(BaseModel):
    full_name: Optional[str] = Field(None, max_length=255)

class SessionSummaryResponse(BaseModel):
    id: int
    created_at: datetime
    expires_at: datetime
    revoked_at: Optional[datetime]
    is_active: bool

    class Config:
        from_attributes = True

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(req: UserRegister, request: Request, db: Session = Depends(get_db)):
    """
    1. User registration with email uniqueness, strong password validation (Argon2id), and audit logging.
    """
    existing_user = db.query(User).filter(User.email == req.email.lower()).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists."
        )

    new_user = User(
        full_name=req.full_name,
        email=req.email.lower(),
        password_hash=hash_password(req.password),
        role="user",
        is_active=True,
        email_verified=False
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    client_ip = request.client.host if (request and hasattr(request, "client") and request.client) else None
    log_audit_event(
        db,
        action="USER_REGISTRATION",
        user_id=new_user.id,
        resource_type="USER",
        resource_id=str(new_user.id),
        ip_address=client_ip
    )

    return new_user

@router.post("/login", response_model=TokenResponse)
def login(req: UserLogin, request: Request, db: Session = Depends(get_db)):
    """
    Login using email & password with failure throttling, Argon2id verification, and refresh-token issuance.
    """
    email_clean = req.email.lower().strip()
    client_ip = request.client.host if (request and hasattr(request, "client") and request.client) else None

    # Check brute-force throttling
    is_throttled, remaining_sec = check_login_throttled(email_clean)
    if is_throttled:
        log_audit_event(
            db,
            action="LOGIN_THROTTLED",
            resource_type="USER",
            resource_id=email_clean,
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Account temporarily locked for {remaining_sec // 60 + 1} minute(s)."
        )

    user = db.query(User).filter(User.email == email_clean).first()

    # Generic error message to prevent account enumeration
    GENERIC_AUTH_ERROR = "Invalid email or password."

    if not user or not verify_password(req.password, user.password_hash):
        record_login_failure(email_clean)
        log_audit_event(
            db,
            action="LOGIN_FAILED",
            resource_type="USER",
            resource_id=email_clean,
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=GENERIC_AUTH_ERROR,
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact an administrator."
        )

    # Authentication succeeded: reset failure throttle
    clear_login_failure(email_clean)

    # Issue short-lived access token
    access_expires_seconds = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    access_token = create_access_token(
        data={"sub": str(user.id), "email": user.email, "role": user.role}
    )

    # Generate long-lived refresh token
    raw_refresh_token, refresh_hash = generate_refresh_token()
    days_valid = settings.REFRESH_TOKEN_REMEMBER_DAYS if req.remember_me else settings.REFRESH_TOKEN_EXPIRE_DAYS
    refresh_expires_at = datetime.now(timezone.utc) + timedelta(days=days_valid)

    # Store refresh token hash securely in user_sessions
    session_record = UserSession(
        user_id=user.id,
        refresh_token_hash=refresh_hash,
        expires_at=refresh_expires_at,
        revoked_at=None
    )
    db.add(session_record)

    log_audit_event(
        db,
        action="LOGIN_SUCCESS",
        user_id=user.id,
        resource_type="USER",
        resource_id=str(user.id),
        ip_address=client_ip
    )
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": raw_refresh_token,
        "token_type": "bearer",
        "expires_in": access_expires_seconds,
        "user": user
    }

@router.post("/refresh", response_model=TokenResponse)
def refresh_token_endpoint(req: RefreshTokenRequest, request: Request, db: Session = Depends(get_db)):
    """
    Refresh-token rotation and revocation:
    Verifies refresh token hash, revokes old session, and issues a new access token and rotated refresh token.
    """
    raw_token = req.refresh_token.strip()
    token_hash = hash_token(raw_token)

    session_record = db.query(UserSession).filter(
        UserSession.refresh_token_hash == token_hash
    ).first()

    if not session_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token."
        )

    if session_record.revoked_at is not None:
        # Potential token reuse attack! Revoke all sessions for this user for security
        db.query(UserSession).filter(UserSession.user_id == session_record.user_id).update(
            {"revoked_at": datetime.now(timezone.utc)}
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Revoked refresh token presented. Security alert: all sessions terminated."
        )

    now = datetime.now(timezone.utc)
    exp = session_record.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp <= now:
        session_record.revoked_at = now
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired. Please log in again."
        )

    # Rotate token: revoke old session
    session_record.revoked_at = now

    user = session_record.user
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is inactive.")

    # Issue new access token & new rotated refresh token
    access_expires_seconds = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    new_access_token = create_access_token(
        data={"sub": str(user.id), "email": user.email, "role": user.role}
    )

    new_raw_refresh, new_refresh_hash = generate_refresh_token()
    new_session = UserSession(
        user_id=user.id,
        refresh_token_hash=new_refresh_hash,
        expires_at=now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        revoked_at=None
    )
    db.add(new_session)
    db.commit()

    return {
        "access_token": new_access_token,
        "refresh_token": new_raw_refresh,
        "token_type": "bearer",
        "expires_in": access_expires_seconds,
        "user": user
    }

@router.post("/logout")
def logout(
    req: Optional[RefreshTokenRequest] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Secure logout: revokes active session refresh token.
    """
    now = datetime.now(timezone.utc)
    if req and req.refresh_token:
        h = hash_token(req.refresh_token)
        db.query(UserSession).filter(
            UserSession.user_id == current_user.id,
            UserSession.refresh_token_hash == h
        ).update({"revoked_at": now})
    else:
        # Revoke all active sessions for current user
        db.query(UserSession).filter(
            UserSession.user_id == current_user.id,
            UserSession.revoked_at.is_(None)
        ).update({"revoked_at": now})

    log_audit_event(
        db,
        action="LOGOUT",
        user_id=current_user.id,
        resource_type="USER",
        resource_id=str(current_user.id)
    )
    db.commit()
    return {"message": "Logged out successfully. Session tokens revoked."}

@router.get("/me", response_model=UserResponse)
def get_profile(current_user: User = Depends(get_current_active_user)):
    return current_user

@router.patch("/me", response_model=UserResponse)
def update_profile(
    req: ProfileUpdateRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    if req.full_name is not None:
        current_user.full_name = req.full_name.strip()
    current_user.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(current_user)

    log_audit_event(
        db,
        action="PROFILE_UPDATED",
        user_id=current_user.id,
        resource_type="USER",
        resource_id=str(current_user.id)
    )
    return current_user

@router.get("/sessions", response_model=List[SessionSummaryResponse])
def get_user_sessions(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    sessions = db.query(UserSession).filter(
        UserSession.user_id == current_user.id
    ).order_by(UserSession.created_at.desc()).limit(15).all()
    return sessions

@router.post("/change-password")
def change_password(
    req: PasswordChangeRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    if not verify_password(req.old_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Current password does not match.")

    current_user.password_hash = hash_password(req.new_password)
    current_user.updated_at = datetime.now(timezone.utc)

    # Invalidate all prior sessions on password change
    db.query(UserSession).filter(
        UserSession.user_id == current_user.id,
        UserSession.revoked_at.is_(None)
    ).update({"revoked_at": datetime.now(timezone.utc)})

    db.commit()

    log_audit_event(
        db,
        action="PASSWORD_CHANGED",
        user_id=current_user.id,
        resource_type="USER",
        resource_id=str(current_user.id)
    )
    return {"message": "Password changed successfully. Prior sessions invalidated."}
