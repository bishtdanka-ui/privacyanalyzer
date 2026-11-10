"""
PrivacyGuard — Centralized Backend API Client
Problem Statement: PS02 - Explainable Cybersecurity Application Privacy & Permission Analyzer

Architectural Controls:
1. Every protected API request attaches an Authorization Bearer header.
2. Intercepts 401 Unauthorized responses to perform automatic refresh-token rotation and retry once.
3. Automatically falls back to the server-side session token if none is explicitly provided.
4. Never trusts client/form-supplied user_id: all backend persistence is scoped to the verified JWT.
5. Handles all analysis, manifest parsing, policy grounding, comparison, reporting, and administration endpoints.
"""

import os
from typing import Dict, Any, Optional, List, Tuple
import requests
import streamlit as st

API_BASE_URL = os.getenv("BACKEND_API_URL", "http://127.0.0.1:8000/api/v1")


class APIClient:
    """
    Centralized HTTP client interacting with the authoritative FastAPI backend.
    """

    def __init__(self, base_url: str = API_BASE_URL):
        self.base_url = base_url.rstrip("/")

    def _get_active_token(self, token: Optional[str] = None) -> Optional[str]:
        if token:
            return token
        try:
            return st.session_state.get("token")
        except Exception:
            return None

    def _headers(self, token: Optional[str] = None) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        active_token = self._get_active_token(token)
        if active_token:
            headers["Authorization"] = f"Bearer {active_token}"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        token: Optional[str] = None,
        auto_refresh: bool = True,
        **kwargs
    ) -> requests.Response:
        """
        Internal request dispatcher with automatic Bearer token injection
        and 401 Unauthorized handling with refresh-token rotation retry.
        """
        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = kwargs.pop("headers", {}) or {}
        active_token = self._get_active_token(token)
        if active_token and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {active_token}"
        kwargs["headers"] = headers

        resp = requests.request(method, url, **kwargs)

        # Transparent refresh-token rotation on 401 Unauthorized
        if resp.status_code == 401 and auto_refresh:
            from frontend.auth_client import auth_client
            if auth_client.refresh_session():
                # Retry once with newly rotated access token
                new_token = auth_client.get_token()
                headers["Authorization"] = f"Bearer {new_token}"
                kwargs["headers"] = headers
                resp = requests.request(method, url, **kwargs)

        return resp

    # =========================================================================
    # AUTHENTICATION & IDENTITY ENDPOINTS
    # =========================================================================

    def register(self, email: str, full_name: str, password: str, terms_accepted: bool = True) -> Tuple[bool, Any]:
        url = f"{self.base_url}/auth/register"
        payload = {
            "email": email.strip().lower(),
            "full_name": full_name or None,
            "password": password,
            "terms_accepted": terms_accepted
        }
        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 201:
                return True, resp.json()
            err_msg = resp.json().get("detail", "Registration failed.")
            if isinstance(err_msg, list) and len(err_msg) > 0:
                err_msg = err_msg[0].get("msg", str(err_msg))
            return False, err_msg
        except Exception as e:
            return False, f"Network connection error: {str(e)}"

    def login(self, email: str, password: str, remember_me: bool = False) -> Tuple[bool, Any]:
        url = f"{self.base_url}/auth/login"
        payload = {
            "email": email.strip().lower(),
            "password": password,
            "remember_me": remember_me
        }
        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            err_msg = resp.json().get("detail", "Invalid email or password.")
            return False, err_msg
        except Exception as e:
            return False, f"Connection failed. Ensure backend is running at {self.base_url}."

    def refresh_access_token(self, refresh_token: str) -> Tuple[bool, Any]:
        url = f"{self.base_url}/auth/refresh"
        payload = {"refresh_token": refresh_token}
        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Session refresh failed.")
        except Exception as e:
            return False, str(e)

    def logout(self, token: Optional[str] = None, refresh_token: Optional[str] = None) -> Tuple[bool, Any]:
        payload = {"refresh_token": refresh_token} if refresh_token else {}
        try:
            resp = self._request("POST", "/auth/logout", token=token, json=payload, auto_refresh=False, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, "Logout failed."
        except Exception as e:
            return False, str(e)

    def get_me(self, token: Optional[str] = None) -> Tuple[bool, Any]:
        try:
            resp = self._request("GET", "/auth/me", token=token, timeout=5)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Unauthorized")
        except Exception as e:
            return False, str(e)

    def update_profile(self, full_name: Optional[str], email: Optional[str], token: Optional[str] = None) -> Tuple[bool, Any]:
        payload: Dict[str, Any] = {}
        if full_name is not None:
            payload["full_name"] = full_name
        if email is not None:
            payload["email"] = email
        try:
            resp = self._request("PATCH", "/auth/me", token=token, json=payload, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to update profile.")
        except Exception as e:
            return False, str(e)

    def change_password(self, old_pwd: str, new_pwd: str, token: Optional[str] = None) -> Tuple[bool, Any]:
        payload = {"old_password": old_pwd, "new_password": new_pwd}
        try:
            resp = self._request("POST", "/auth/change-password", token=token, json=payload, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to change password.")
        except Exception as e:
            return False, str(e)

    def get_sessions(self, token: Optional[str] = None) -> Tuple[bool, Any]:
        try:
            resp = self._request("GET", "/auth/sessions", token=token, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to load sessions.")
        except Exception as e:
            return False, str(e)

    # =========================================================================
    # CORE ANALYSIS ENDPOINTS
    # =========================================================================

    def analyze_manifest_text(
        self,
        manifest_xml: str,
        policy_text: Optional[str] = None,
        token: Optional[str] = None
    ) -> Tuple[bool, Any]:
        payload = {
            "manifest_xml": manifest_xml,
            "privacy_policy_text": policy_text or None
        }
        try:
            resp = self._request("POST", "/analysis/analyze", token=token, json=payload, timeout=25)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Analysis failed.")
        except Exception as e:
            return False, f"Request failed: {str(e)}"

    def analyze_manifest_v1(
        self,
        manifest_xml: str,
        token: Optional[str] = None,
        source_file: str = "AndroidManifest.xml",
        policy_text: Optional[str] = None
    ) -> Tuple[bool, Any]:
        payload = {
            "manifest_xml": manifest_xml,
            "source_file": source_file,
            "privacy_policy_text": policy_text or None
        }
        try:
            resp = self._request("POST", "/analyze/manifest", token=token, json=payload, timeout=25)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Manifest extraction analysis failed.")
        except Exception as e:
            return False, f"Request failed: {str(e)}"

    def analyze_privacy_policy(
        self,
        policy_text: str,
        token: Optional[str] = None,
        app_name: Optional[str] = None,
        analysis_id: Optional[int] = None
    ) -> Tuple[bool, Any]:
        payload = {
            "policy_text": policy_text,
            "app_name": app_name or "Privacy Policy Evaluation",
            "analysis_id": analysis_id
        }
        try:
            resp = self._request("POST", "/analyze/policy", token=token, json=payload, timeout=25)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Privacy policy analysis failed.")
        except Exception as e:
            return False, f"Request failed: {str(e)}"

    def compare_purpose(
        self,
        token: Optional[str] = None,
        app_name: Optional[str] = None,
        app_purpose: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        manifest_xml: Optional[str] = None,
        privacy_policy_text: Optional[str] = None,
        analysis_id: Optional[int] = None
    ) -> Tuple[bool, Any]:
        payload = {
            "app_name": app_name or "Application",
            "app_purpose": app_purpose,
            "permissions": permissions,
            "manifest_xml": manifest_xml,
            "privacy_policy_text": privacy_policy_text,
            "analysis_id": analysis_id
        }
        try:
            resp = self._request("POST", "/analyze/compare", token=token, json=payload, timeout=25)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Purpose comparison failed.")
        except Exception as e:
            return False, f"Request failed: {str(e)}"

    def get_analysis_findings(self, analysis_id: int, token: Optional[str] = None) -> Tuple[bool, Any]:
        try:
            resp = self._request("GET", f"/analyses/{analysis_id}/findings", token=token, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to retrieve findings.")
        except Exception as e:
            return False, f"Request failed: {str(e)}"

    def upload_manifest(
        self,
        manifest_bytes: bytes,
        manifest_filename: str,
        policy_text: Optional[str] = None,
        policy_bytes: Optional[bytes] = None,
        policy_filename: Optional[str] = None,
        token: Optional[str] = None
    ) -> Tuple[bool, Any]:
        files = {
            "manifest_file": (manifest_filename, manifest_bytes, "application/xml")
        }
        if policy_bytes and policy_filename:
            files["policy_file"] = (policy_filename, policy_bytes, "text/plain")

        data = {}
        if policy_text:
            data["policy_text"] = policy_text

        try:
            resp = self._request(
                "POST",
                "/analysis/upload",
                token=token,
                files=files,
                data=data,
                timeout=30
            )
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "File analysis failed.")
        except Exception as e:
            return False, f"Upload error: {str(e)}"

    def get_dashboard_metrics(self, token: Optional[str] = None) -> Tuple[bool, Any]:
        try:
            resp = self._request("GET", "/analysis/dashboard/metrics", token=token, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to load dashboard metrics.")
        except Exception as e:
            return False, str(e)

    def get_history(self, token: Optional[str] = None) -> Tuple[bool, Any]:
        try:
            resp = self._request("GET", "/analysis/history", token=token, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to load history.")
        except Exception as e:
            return False, str(e)

    def get_analysis_details(self, analysis_id: int, token: Optional[str] = None) -> Tuple[bool, Any]:
        try:
            resp = self._request("GET", f"/analysis/{analysis_id}", token=token, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Analysis record not found.")
        except Exception as e:
            return False, str(e)

    def download_report(
        self,
        analysis_id: int,
        token: Optional[str] = None,
        format: str = "pdf",
        section: Optional[str] = None
    ) -> Tuple[bool, Any]:
        params = {"format": format}
        if section:
            params["section"] = section

        try:
            resp = self._request("GET", f"/analyses/{analysis_id}/report", token=token, params=params, timeout=30)
            if resp.status_code == 200:
                if format.lower() == "json":
                    return True, resp.json()
                elif format.lower() == "csv":
                    return True, resp.text
                return True, resp.content
            return False, f"Failed to download report ({resp.status_code}): {resp.text}"
        except Exception as e:
            return False, str(e)

    def download_pdf(self, analysis_id: int, token: Optional[str] = None) -> Tuple[bool, Any]:
        return self.download_report(analysis_id, token, format="pdf")

    def delete_analysis(self, analysis_id: int, token: Optional[str] = None) -> Tuple[bool, Any]:
        try:
            resp = self._request("DELETE", f"/analysis/{analysis_id}", token=token, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, "Failed to delete record."
        except Exception as e:
            return False, str(e)

    # =========================================================================
    # ADMINISTRATOR & GOVERNANCE ENDPOINTS
    # =========================================================================

    def get_admin_stats(self, token: Optional[str] = None) -> Tuple[bool, Any]:
        try:
            resp = self._request("GET", "/admin/stats", token=token, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to retrieve stats.")
        except Exception as e:
            return False, str(e)

    def get_admin_health(self, token: Optional[str] = None) -> Tuple[bool, Any]:
        try:
            resp = self._request("GET", "/admin/health", token=token, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to retrieve health status.")
        except Exception as e:
            return False, str(e)

    def get_admin_users(
        self,
        token: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
        search: Optional[str] = None,
        role: Optional[str] = None,
        is_active: Optional[bool] = None
    ) -> Tuple[bool, Any]:
        params: Dict[str, Any] = {"page": page, "page_size": page_size}
        if search:
            params["search"] = search
        if role:
            params["role"] = role
        if is_active is not None:
            params["is_active"] = is_active

        try:
            resp = self._request("GET", "/admin/users", token=token, params=params, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to retrieve users.")
        except Exception as e:
            return False, str(e)

    def update_admin_user(self, user_id: int, req_data: Dict[str, Any], token: Optional[str] = None) -> Tuple[bool, Any]:
        try:
            resp = self._request("PATCH", f"/admin/users/{user_id}", token=token, json=req_data, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to update user.")
        except Exception as e:
            return False, str(e)

    def get_admin_analyses(
        self,
        token: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
        search: Optional[str] = None,
        risk_level: Optional[str] = None
    ) -> Tuple[bool, Any]:
        params: Dict[str, Any] = {"page": page, "page_size": page_size}
        if search:
            params["search"] = search
        if risk_level:
            params["risk_level"] = risk_level

        try:
            resp = self._request("GET", "/admin/analyses", token=token, params=params, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to retrieve analyses.")
        except Exception as e:
            return False, str(e)

    def get_admin_audit_logs(
        self,
        token: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
        action: Optional[str] = None,
        user_id: Optional[int] = None
    ) -> Tuple[bool, Any]:
        params: Dict[str, Any] = {"page": page, "page_size": page_size}
        if action:
            params["action"] = action
        if user_id:
            params["user_id"] = user_id

        try:
            resp = self._request("GET", "/admin/audit-logs", token=token, params=params, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to retrieve audit logs.")
        except Exception as e:
            return False, str(e)

    def get_admin_knowledge_base(
        self,
        token: Optional[str] = None,
        search: Optional[str] = None,
        category: Optional[str] = None,
        risk_level: Optional[str] = None,
        protection_level: Optional[str] = None
    ) -> Tuple[bool, Any]:
        params: Dict[str, Any] = {}
        if search:
            params["search"] = search
        if category:
            params["category"] = category
        if risk_level:
            params["risk_level"] = risk_level
        if protection_level:
            params["protection_level"] = protection_level

        try:
            resp = self._request("GET", "/admin/knowledge-base", token=token, params=params, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to retrieve knowledge base.")
        except Exception as e:
            return False, str(e)

    def validate_kb_entry(self, entry_payload: Dict[str, Any], token: Optional[str] = None) -> Tuple[bool, Any]:
        try:
            resp = self._request("POST", "/admin/knowledge-base/validate", token=token, json=entry_payload, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Schema validation failed.")
        except Exception as e:
            return False, str(e)

    def publish_kb_entry(self, entry_payload: Dict[str, Any], token: Optional[str] = None) -> Tuple[bool, Any]:
        try:
            resp = self._request("POST", "/admin/knowledge-base/entries", token=token, json=entry_payload, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to publish entry.")
        except Exception as e:
            return False, str(e)


# Global singleton instance
api_client = APIClient()
