from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.user import User
from backend.schemas.auth import UserRegister, UserLogin, TokenResponse, UserResponse, PasswordChangeRequest
from backend.security.hashing import hash_password, verify_password
from backend.security.jwt_auth import create_access_token
from backend.security.dependencies import get_current_active_user
from backend.services.audit_service import log_audit_event

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(req: UserRegister, request: Request, db: Session = Depends(get_db)):
    # Check existing user
    if db.query(User).filter(User.email == req.email.lower()).first():
        raise HTTPException(status_code=400, detail="An account with this email already exists.")
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(status_code=400, detail="Username is already taken.")

    # Create user
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

    client_ip = request.client.host if request.client else "unknown"

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

    # Issue token
    token = create_access_token(data={"sub": str(user.id), "role": user.role, "username": user.username})

    log_audit_event(
        db,
        action="LOGIN_SUCCESS",
        user_id=user.id,
        target_type="USER",
        target_id=str(user.id),
        details={"username": user.username},
        ip_address=client_ip
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user
    }

@router.get("/me", response_model=UserResponse)
def get_profile(current_user: User = Depends(get_current_active_user)):
    return current_user

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
