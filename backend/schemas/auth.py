from datetime import datetime
from typing import Optional
import re
from pydantic import BaseModel, Field, field_validator, ConfigDict
from backend.security.hashing import validate_password_strength

class UserRegister(BaseModel):
    full_name: Optional[str] = Field(None, max_length=255)
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    terms_accepted: bool = Field(True, description="User accepted terms of service")

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        pattern = r"^[\w\.\+\-]+@[\w\-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, v.strip()):
            raise ValueError("Invalid email format.")
        return v.lower().strip()

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        is_strong, msg = validate_password_strength(v)
        if not is_strong:
            raise ValueError(msg)
        return v

    @field_validator("terms_accepted")
    @classmethod
    def validate_terms(cls, v: bool) -> bool:
        if not v:
            raise ValueError("You must accept the terms of service to register.")
        return v

class UserLogin(BaseModel):
    email: str
    password: str
    remember_me: bool = False

    @field_validator("email")
    @classmethod
    def clean_email(cls, v: str) -> str:
        return v.lower().strip()

class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(..., min_length=10)

class UserResponse(BaseModel):
    id: int
    full_name: Optional[str] = None
    email: str
    role: str
    is_active: bool
    email_verified: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse

class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        is_strong, msg = validate_password_strength(v)
        if not is_strong:
            raise ValueError(msg)
        return v
