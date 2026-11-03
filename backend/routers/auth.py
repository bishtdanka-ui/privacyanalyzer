from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from backend.config import settings
from backend.database import get_db
from backend.models.user import User
from backend.models.user_session import UserSession
from backend.schemas.auth import UserRegister, UserLogin, TokenResponse, UserResponse, PasswordChangeRequest
from backend.security.hashing import hash_password, verify_password
from backend.security.jwt_auth import create_access_token
from backend.security.dependencies import get_current_active_user
from backend.services.audit_service import log_audit_event

router = APIRouter(prefix="/auth", tags=["Authentication"])

class ProfileUpdateRequest(BaseModel):
    full_name: Optional[str] = None
    email: Optional[str] = None

class UserSessionResponse(BaseModel):
    id: int
    ip_address: Optional[str]
    user_agent: Optional[str]
    is_active: bool
    created_at: datetime
    expires_at: datetime

    class Config:
        from_attributes = True

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(req: UserRegister, request: Request, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == req.email.lower()).first():
        raise HTTPException(status_code=400, detail="An account with this email already exists.")
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(status_code=400, detail="Username is already taken.")

    new_user = User(
        email=req.email.lower(),
        username=req.username,
        full_name=req.full_name,
        hashed_password=hash_password(req.password),
        role="user",
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    client_ip = request.client.host if request.client else "unknown"
    log_audit_event(
        db,
        action="USER_REGISTRATION",
        user_id=new_user.id,
        target_type="USER",
        target_id=str(new_user.id),
        details={"username": new_user.username, "email": new_user.email},
        ip_address=client_ip
    )

    return new_user

@router.post("/login", response_model=TokenResponse)
def login(req: UserLogin, request: Request, db: Session = Depends(get_db)):
    identifier = req.username_or_email.strip().lower()
    user = db.query(User).filter(
        (User.email == identifier) | (User.username == req.username_or_email.strip())
    ).first()

    client_ip = request.client.host if (request and hasattr(request, "client") and request.client) else "unknown"
    user_agent = "unknown"
    if request and hasattr(request, "headers"):
        ua_val = request.headers.get("user-agent")
        if isinstance(ua_val, str):
            user_agent = ua_val[:255]

    if not user or not verify_password(req.password, user.hashed_password):
        log_audit_event(
            db,
            action="LOGIN_FAILED",
            target_type="USER",
            target_id=identifier,
            details={"reason": "Invalid credentials", "identifier": identifier},
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact an administrator."
        )

    # Issue JWT token
    token = create_access_token(data={"sub": str(user.id), "role": user.role, "username": user.username})
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    # Persist session to user_sessions table
    session_record = UserSession(
        user_id=user.id,
        session_token=token,
        ip_address=client_ip,
        user_agent=user_agent,
        is_active=True,
        expires_at=expires_at
    )
    db.add(session_record)

    log_audit_event(
        db,
        action="LOGIN_SUCCESS",
        user_id=user.id,
        target_type="USER",
        target_id=str(user.id),
        details={"username": user.username, "session_id": session_record.id},
        ip_address=client_ip
    )
    db.commit()

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user
    }

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
    if req.email is not None and req.email.lower() != current_user.email:
        existing = db.query(User).filter(User.email == req.email.lower()).first()
        if existing and existing.id != current_user.id:
            raise HTTPException(status_code=400, detail="This email address is already in use.")
        current_user.email = req.email.lower().strip()
    
    db.commit()
    db.refresh(current_user)
    
    log_audit_event(
        db,
        action="PROFILE_UPDATED",
        user_id=current_user.id,
        target_type="USER",
        target_id=str(current_user.id)
    )
    return current_user

@router.get("/sessions", response_model=List[UserSessionResponse])
def get_user_sessions(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    sessions = db.query(UserSession).filter(
        UserSession.user_id == current_user.id
    ).order_by(UserSession.created_at.desc()).limit(10).all()
    return sessions

@router.post("/change-password")
def change_password(
    req: PasswordChangeRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    if not verify_password(req.old_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password does not match.")
    
    current_user.hashed_password = hash_password(req.new_password)
    db.commit()
    
    log_audit_event(
        db,
        action="PASSWORD_CHANGED",
        user_id=current_user.id,
        target_type="USER",
        target_id=str(current_user.id)
    )
    return {"message": "Password changed successfully."}
