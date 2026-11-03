import json
import logging
from typing import Dict, Any, List, Optional
from backend.config import settings

logger = logging.getLogger(__name__)

class PermissionKnowledgeBase:
    _instance = None
    _kb_data: Dict[str, Any] = {}

    @classmethod
    def get_instance(cls) -> "PermissionKnowledgeBase":
        if cls._instance is None:
            cls._instance = cls()
            cls._instance.load()
        return cls._instance

    def load(self):
        try:
            if settings.KB_PATH.exists():
                with open(settings.KB_PATH, "r", encoding="utf-8") as f:
                    self._kb_data = json.load(f)
                logger.info(f"Loaded {len(self._kb_data.get('permissions', {}))} permissions from KB.")
            else:
                logger.warning(f"KB file not found at {settings.KB_PATH}")
                self._kb_data = {"permissions": {}, "combo_rules": []}
        except Exception as e:
            logger.error(f"Failed to load permission KB: {e}")
            self._kb_data = {"permissions": {}, "combo_rules": []}

    def get_permission(self, perm_name: str) -> Dict[str, Any]:
        """
        Lookup permission metadata. Handles full canonical names or bare names.
        """
        clean_name = perm_name.strip()
        permissions = self._kb_data.get("permissions", {})
        
        # Exact match
        if clean_name in permissions:
            return permissions[clean_name]
        
        # Try prepending android.permission.
        prefixed = f"android.permission.{clean_name}"
        if prefixed in permissions:
            return permissions[prefixed]

        # Unknown / custom / third-party permission fallback
        short = clean_name.split(".")[-1]
        is_suspicious_custom = any(kw in clean_name.lower() for kw in ["root", "admin", "inject", "hook", "exploit"])
        
        return {
            "short_name": short,
            "group": "Custom/Unknown",
            "protection_level": "special" if is_suspicious_custom else "normal",
            "description": f"Custom or vendor-specific permission: {clean_name}",
            "privacy_risk": "Custom permissions may grant internal IPC or proprietary service access not governed by standard Android sandbox gates.",
            "abuse_scenarios": ["Privilege escalation via custom OEM interfaces or unprotected inter-app broadcast channels."],
            "privacy_keywords": [short.lower()],
            "severity_score": 5.0 if is_suspicious_custom else 2.5,
            "remediation": "Audit custom permission definitions to ensure proper protectionLevel='signature' is enforced."
        }

    def get_combo_rules(self) -> List[Dict[str, Any]]:
        return self._kb_data.get("combo_rules", [])

permission_kb = PermissionKnowledgeBase.get_instance()
