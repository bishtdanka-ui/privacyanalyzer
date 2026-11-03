from datetime import datetime
from typing import Optional
import re
from pydantic import BaseModel, Field, field_validator, ConfigDict

class UserRegister(BaseModel):
    email: str = Field(..., min_length=5, max_length=255)
    username: str = Field(..., min_length=3, max_length=50)
    full_name: Optional[str] = None
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        pattern = r"^[\w\.\+\-]+@[\w\-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError("Invalid email format.")
        return v.lower().strip()

class UserLogin(BaseModel):
    username_or_email: str
    password: str

class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    full_name: Optional[str]
    role: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8, max_length=128)
