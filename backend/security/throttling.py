from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple
from backend.config import settings

# Thread-safe in-memory store for tracking failed login attempts: {identifier: (attempts_count, last_attempt_time)}
_login_failures: Dict[str, Tuple[int, datetime]] = {}

def check_login_throttled(identifier: str) -> Tuple[bool, int]:
    """
    Check if the identifier (email or IP) is currently locked out.
    Returns (is_throttled, remaining_lockout_seconds).
    """
    key = identifier.strip().lower()
    if key not in _login_failures:
        return False, 0

    count, last_time = _login_failures[key]
    if count >= settings.MAX_LOGIN_ATTEMPTS:
        elapsed = datetime.now(timezone.utc) - last_time
        lockout_duration = timedelta(minutes=settings.LOCKOUT_MINUTES)
        if elapsed < lockout_duration:
            remaining = int((lockout_duration - elapsed).total_seconds())
            return True, remaining
        else:
            # Lockout period expired; reset counter
            del _login_failures[key]
            return False, 0

    return False, 0

def record_login_failure(identifier: str):
    """
    Record an unsuccessful login attempt for the identifier.
    """
    key = identifier.strip().lower()
    now = datetime.now(timezone.utc)
    if key in _login_failures:
        count, _ = _login_failures[key]
        _login_failures[key] = (count + 1, now)
    else:
        _login_failures[key] = (1, now)

def clear_login_failure(identifier: str):
    """
    Clear failed login attempts upon successful authentication.
    """
    key = identifier.strip().lower()
    if key in _login_failures:
        del _login_failures[key]

