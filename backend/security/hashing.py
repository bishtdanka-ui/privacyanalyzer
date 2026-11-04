import re
import hashlib
import secrets
from typing import Tuple
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

# Configure Argon2id Password Hasher with OWASP recommended parameters
ph = PasswordHasher(
    time_cost=3,        # 3 iterations
    memory_cost=65536,  # 64 MiB
    parallelism=4,      # 4 parallel threads
    hash_len=32,
    salt_len=16
)

def hash_password(password: str) -> str:
    """
    Hash a plaintext password using Argon2id.
    """
    return ph.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against an Argon2id hash.
    Constant-time comparison is built into Argon2 verify.
    """
    try:
        return ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, InvalidHashError):
        return False
    except Exception:
        return False

def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate that password meets enterprise security standards:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>\-_=+/\\\[\]~`]", password):
        return False, "Password must contain at least one special character."
    return True, "Strong password."

def generate_refresh_token() -> Tuple[str, str]:
    """
    Generate a cryptographically secure random refresh token (opaque URL-safe string).
    Returns (raw_token, token_hash).
    Only token_hash is stored in the database.
    """
    raw_token = secrets.token_urlsafe(64)
    token_hash = hash_token(raw_token)
    return raw_token, token_hash

def hash_token(token: str) -> str:
    """
    Compute cryptographic SHA-256 digest of token for secure lookup and storage.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
