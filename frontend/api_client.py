import os
from typing import Dict, Any, Optional, List, Tuple
import requests

API_BASE_URL = os.getenv("BACKEND_API_URL", "http://127.0.0.1:8000/api/v1")

class APIClient:
    def __init__(self, base_url: str = API_BASE_URL):
        self.base_url = base_url.rstrip("/")

    def _headers(self, token: Optional[str] = None) -> Dict[str, str]:
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def register(self, email: str, username: str, full_name: str, password: str) -> Tuple[bool, Any]:
        url = f"{self.base_url}/auth/register"
        payload = {
            "email": email,
            "username": username,
            "full_name": full_name or None,
            "password": password
        }
        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 201:
                return True, resp.json()
            return False, resp.json().get("detail", "Registration failed.")
        except Exception as e:
            return False, f"Network connection error: {str(e)}"

    def login(self, username_or_email: str, password: str) -> Tuple[bool, Any]:
        url = f"{self.base_url}/auth/login"
        payload = {
            "username_or_email": username_or_email,
            "password": password
        }
        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Invalid username or password.")
        except Exception as e:
            return False, f"Connection failed. Ensure backend is running at {self.base_url}."

    def get_me(self, token: str) -> Tuple[bool, Any]:
        url = f"{self.base_url}/auth/me"
        try:
            resp = requests.get(url, headers=self._headers(token), timeout=5)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Unauthorized")
        except Exception as e:
            return False, str(e)

    def update_profile(self, full_name: Optional[str], email: Optional[str], token: str) -> Tuple[bool, Any]:
        url = f"{self.base_url}/auth/me"
        payload = {}
        if full_name is not None:
            payload["full_name"] = full_name
        if email is not None:
            payload["email"] = email
        try:
            resp = requests.patch(url, json=payload, headers=self._headers(token), timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to update profile.")
        except Exception as e:
            return False, str(e)

    def change_password(self, old_pwd: str, new_pwd: str, token: str) -> Tuple[bool, Any]:
        url = f"{self.base_url}/auth/change-password"
        payload = {"old_password": old_pwd, "new_password": new_pwd}
        try:
            resp = requests.post(url, json=payload, headers=self._headers(token), timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to change password.")
        except Exception as e:
            return False, str(e)

    def get_sessions(self, token: str) -> Tuple[bool, Any]:
        url = f"{self.base_url}/auth/sessions"
        try:
            resp = requests.get(url, headers=self._headers(token), timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to load sessions.")
        except Exception as e:
            return False, str(e)

    def analyze_manifest_text(
        self,
        manifest_xml: str,
        policy_text: Optional[str],
        token: str
    ) -> Tuple[bool, Any]:
        url = f"{self.base_url}/analysis/analyze"
        payload = {
            "manifest_xml": manifest_xml,
            "privacy_policy_text": policy_text or None
        }
        try:
            resp = requests.post(url, json=payload, headers=self._headers(token), timeout=25)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Analysis failed.")
        except Exception as e:
            return False, f"Request failed: {str(e)}"

    def upload_manifest(
        self,
        manifest_bytes: bytes,
        manifest_filename: str,
        policy_text: Optional[str],
        policy_bytes: Optional[bytes],
        policy_filename: Optional[str],
        token: str
    ) -> Tuple[bool, Any]:
        url = f"{self.base_url}/analysis/upload"
        files = {
            "manifest_file": (manifest_filename, manifest_bytes, "application/xml")
        }
        if policy_bytes and policy_filename:
            files["policy_file"] = (policy_filename, policy_bytes, "text/plain")

        data = {}
        if policy_text:
            data["policy_text"] = policy_text

        try:
            resp = requests.post(
                url,
                files=files,
                data=data,
                headers=self._headers(token),
                timeout=30
            )
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "File analysis failed.")
        except Exception as e:
            return False, f"Upload error: {str(e)}"

    def get_history(self, token: str) -> Tuple[bool, Any]:
        url = f"{self.base_url}/analysis/history"
        try:
            resp = requests.get(url, headers=self._headers(token), timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to load history.")
        except Exception as e:
            return False, str(e)

    def get_analysis_details(self, analysis_id: int, token: str) -> Tuple[bool, Any]:
        url = f"{self.base_url}/analysis/{analysis_id}"
        try:
            resp = requests.get(url, headers=self._headers(token), timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Analysis record not found.")
        except Exception as e:
            return False, str(e)

    def download_pdf(self, analysis_id: int, token: str) -> Tuple[bool, Any]:
        url = f"{self.base_url}/analysis/{analysis_id}/pdf"
        try:
            resp = requests.get(url, headers=self._headers(token), timeout=20)
            if resp.status_code == 200:
                return True, resp.content
            return False, "Failed to download PDF."
        except Exception as e:
            return False, str(e)

    def delete_analysis(self, analysis_id: int, token: str) -> Tuple[bool, Any]:
        url = f"{self.base_url}/analysis/{analysis_id}"
        try:
            resp = requests.delete(url, headers=self._headers(token), timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, "Failed to delete record."
        except Exception as e:
            return False, str(e)

    def get_admin_stats(self, token: str) -> Tuple[bool, Any]:
        url = f"{self.base_url}/admin/stats"
        try:
            resp = requests.get(url, headers=self._headers(token), timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to retrieve stats.")
        except Exception as e:
            return False, str(e)

    def get_admin_users(self, token: str) -> Tuple[bool, Any]:
        url = f"{self.base_url}/admin/users"
        try:
            resp = requests.get(url, headers=self._headers(token), timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to retrieve users.")
        except Exception as e:
            return False, str(e)

    def update_admin_user(self, user_id: int, req_data: Dict[str, Any], token: str) -> Tuple[bool, Any]:
        url = f"{self.base_url}/admin/users/{user_id}"
        try:
            resp = requests.patch(url, json=req_data, headers=self._headers(token), timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to update user.")
        except Exception as e:
            return False, str(e)

    def get_admin_audit_logs(self, limit: int, token: str) -> Tuple[bool, Any]:
        url = f"{self.base_url}/admin/audit-logs?limit={limit}"
        try:
            resp = requests.get(url, headers=self._headers(token), timeout=10)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", "Failed to retrieve audit logs.")
        except Exception as e:
            return False, str(e)

api_client = APIClient()

