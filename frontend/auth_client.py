"""
PrivacyGuard — Centralized Authentication Client
Problem Statement: PS02 - Explainable Cybersecurity Application Privacy & Permission Analyzer

Architectural Controls:
1. FastAPI is the sole authority for authentication, token generation, and password validation.
2. Streamlit never authenticates users independently.
3. Authenticated session state is stored exclusively in server-side Streamlit session (`st.session_state`).
4. Never puts passwords or refresh tokens in URLs or browser localStorage.
5. Implements short-lived access tokens and refresh-token rotation.
6. Session expiration and logout cleanly revoke backend database session hashes.
7. User identity is fetched strictly from verified backend responses.
"""

import os
from typing import Dict, Any, Optional, Tuple
import requests
import streamlit as st

API_BASE_URL = os.getenv("BACKEND_API_URL", "http://127.0.0.1:8000/api/v1")


class AuthClient:
    """
    Centralized authentication manager coordinating Streamlit frontend
    with the authoritative FastAPI backend security services.
    """

    def __init__(self, base_url: str = API_BASE_URL):
        self.base_url = base_url.rstrip("/")

    def get_token(self) -> Optional[str]:
        """Safely retrieve access token from server-side Streamlit session."""
        try:
            return st.session_state.get("token")
        except Exception:
            return None

    def get_refresh_token(self) -> Optional[str]:
        """Safely retrieve refresh token from server-side Streamlit session."""
        try:
            return st.session_state.get("refresh_token")
        except Exception:
            return None

    def get_current_user(self) -> Optional[Dict[str, Any]]:
        """Safely retrieve authenticated user context from server-side Streamlit session."""
        try:
            return st.session_state.get("user")
        except Exception:
            return None

    def is_authenticated(self) -> bool:
        """
        Returns True only when valid session token and user context exist in server-side state.
        Never relies on unauthenticated local storage.
        """
        return bool(self.get_token() and self.get_current_user())

    def is_admin(self) -> bool:
        """Determines if the active user possesses the administrator role."""
        user = self.get_current_user()
        return bool(user and user.get("role") == "admin")

    def register(
        self,
        email: str,
        full_name: str,
        password: str,
        terms_accepted: bool = True
    ) -> Tuple[bool, Any]:
        """
        Register a new user through the authoritative FastAPI endpoint.
        Streamlit performs zero local account creation or hashing.
        """
        url = f"{self.base_url}/auth/register"
        payload = {
            "email": email.strip().lower(),
            "full_name": full_name.strip() if full_name else None,
            "password": password,
            "terms_accepted": terms_accepted
        }
        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 201:
                return True, resp.json()
            err = resp.json().get("detail", "Registration failed.")
            if isinstance(err, list) and len(err) > 0:
                err = err[0].get("msg", str(err))
            return False, err
        except Exception as e:
            return False, f"Connection to authentication service failed: {str(e)}"

    def login(
        self,
        email: str,
        password: str,
        remember_me: bool = False
    ) -> Tuple[bool, Any]:
        """
        Authenticate credentials against authoritative FastAPI backend.
        On success, stores short-lived access token, rotating refresh token,
        and verified user identity exclusively in server-side session.
        Never puts credentials or tokens in URL parameters or browser storage.
        """
        url = f"{self.base_url}/auth/login"
        payload = {
            "email": email.strip().lower(),
            "password": password,
            "remember_me": remember_me
        }
        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                access_token = data.get("access_token")
                refresh_token = data.get("refresh_token")
                user = data.get("user")

                # Store securely in server-side session
                st.session_state["token"] = access_token
                st.session_state["refresh_token"] = refresh_token
                st.session_state["user"] = user
                st.session_state["current_page"] = "Dashboard"

                return True, data
            err = resp.json().get("detail", "Invalid email or password.")
            return False, err
        except Exception as e:
            return False, f"Connection failed. Ensure backend is running at {self.base_url}."

    def refresh_session(self) -> bool:
        """
        Execute refresh-token rotation with the backend.
        Invalidates old refresh token in database, obtains new access token and rotated refresh token,
        and updates server-side session state.
        Returns True if session was refreshed, False if session is invalid or expired.
        """
        refresh_token = self.get_refresh_token()
        if not refresh_token:
            self.clear_session()
            return False

        url = f"{self.base_url}/auth/refresh"
        try:
            resp = requests.post(url, json={"refresh_token": refresh_token}, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                st.session_state["token"] = data.get("access_token")
                st.session_state["refresh_token"] = data.get("refresh_token")
                if data.get("user"):
                    st.session_state["user"] = data.get("user")
                return True
            else:
                # Refresh token invalid or revoked
                self.clear_session()
                return False
        except Exception:
            return False

    def sync_session(self) -> bool:
        """
        Verifies active session with backend authority (/auth/me).
        If access token has expired, attempts automatic refresh-token rotation.
        Updates user identity from authoritative response.
        """
        token = self.get_token()
        if not token:
            return False

        url = f"{self.base_url}/auth/me"
        try:
            resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=5)
            if resp.status_code == 200:
                # Update user state with authoritative data from backend
                st.session_state["user"] = resp.json()
                return True
            elif resp.status_code == 401:
                # Token expired, try automatic refresh-token rotation
                return self.refresh_session()
            else:
                self.clear_session()
                return False
        except Exception:
            # Network issue or server reboot: preserve state if token present
            return True

    def logout(self) -> bool:
        """
        Authoritative logout: calls backend /auth/logout with active refresh token,
        permanently revoking the session hash in database, and clears server-side state.
        """
        token = self.get_token()
        refresh_token = self.get_refresh_token()

        if token:
            url = f"{self.base_url}/auth/logout"
            payload = {"refresh_token": refresh_token} if refresh_token else {}
            try:
                requests.post(
                    url,
                    json=payload,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=5
                )
            except Exception:
                pass

        self.clear_session()
        return True

    def clear_session(self):
        """Safely clear server-side session state without touching URLs or browser storage."""
        st.session_state["token"] = None
        st.session_state["refresh_token"] = None
        st.session_state["user"] = None
        st.session_state["active_analysis"] = None
        st.session_state["current_page"] = "Dashboard"


# Global singleton instance
auth_client = AuthClient()

