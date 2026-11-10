import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_KB_PATH = Path(__file__).resolve().parent / "android_permissions.json"

class PermissionLookupService:
    def __init__(self, kb_path: Optional[Path] = None):
        self.kb_path = kb_path or DEFAULT_KB_PATH
        self._entries: Dict[str, Dict[str, Any]] = {}
        self.load_knowledge_base()

    def load_knowledge_base(self):
        """
        Load or reload the structured permissions knowledge base from disk.
        Allows expanding the JSON knowledge base at runtime without altering the engine.
        Supports:
        - Root dictionary keyed by permission name
        - Dict with 'permissions' as a sub-dictionary
        - Dict with 'permissions' as a list of permission objects
        - Root list of permission objects
        """
        try:
            if self.kb_path.exists():
                with open(self.kb_path, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)

                entries_map: Dict[str, Dict[str, Any]] = {}

                if isinstance(raw_data, list):
                    for item in raw_data:
                        if isinstance(item, dict) and "permission" in item:
                            entries_map[item["permission"].strip()] = item
                elif isinstance(raw_data, dict):
                    perms = raw_data.get("permissions", raw_data)
                    if isinstance(perms, list):
                        for item in perms:
                            if isinstance(item, dict) and "permission" in item:
                                entries_map[item["permission"].strip()] = item
                    elif isinstance(perms, dict):
                        for k, v in perms.items():
                            if isinstance(v, dict):
                                entries_map[k.strip()] = v

                # Normalize each entry to guarantee standard fields and non-empty explanation
                for perm_id, entry in entries_map.items():
                    if not entry.get("explanation") or not str(entry.get("explanation")).strip():
                        display_name = entry.get("display_name", perm_id.split(".")[-1])
                        entry["explanation"] = (
                            f"This application declares {display_name}. "
                            f"This declaration alone does not prove that the capability has been used or granted at runtime."
                        )

                self._entries = entries_map
                logger.info(f"Loaded {len(self._entries)} permission entries from {self.kb_path.name}")
            else:
                logger.warning(f"Knowledge base file not found at {self.kb_path}")
                self._entries = {}
        except Exception as e:
            logger.error(f"Failed to parse knowledge base: {e}")
            self._entries = {}

    def get_entry_count(self) -> int:
        return len(self._entries)

    def lookup(self, permission_identifier: str) -> Dict[str, Any]:
        """
        Look up a permission by its canonical name or short identifier.
        If no reliable entry exists, returns a structured UNKNOWN response.
        Never invents explanations for unknown permissions.
        """
        if not permission_identifier or not permission_identifier.strip():
            return self._build_unknown_entry("")

        clean_id = permission_identifier.strip()
        found_entry = None

        # 1. Exact match on canonical identifier
        if clean_id in self._entries:
            found_entry = self._entries[clean_id]
        # 2. Match with prepended 'android.permission.'
        elif f"android.permission.{clean_id}" in self._entries:
            found_entry = self._entries[f"android.permission.{clean_id}"]
        else:
            # 3. Case-insensitive lookup fallback
            lower_id = clean_id.lower()
            for k, v in self._entries.items():
                if k.lower() == lower_id or k.lower() == f"android.permission.{lower_id}":
                    found_entry = v
                    break

        if found_entry:
            entry = dict(found_entry)
            entry["is_known"] = True
            # Compatibility helpers for analysis engine
            entry["group"] = entry.get("category", "General")
            entry["short_name"] = entry.get("permission", clean_id).split(".")[-1]
            if "severity_score" not in entry:
                risk_map = {
                    "CRITICAL": 9.5,
                    "HIGH": 8.0,
                    "MEDIUM": 5.5,
                    "CONTEXT_DEPENDENT": 5.5,
                    "LOW": 3.0,
                    "NEGLIGIBLE": 1.0
                }
                entry["severity_score"] = risk_map.get(entry.get("risk_level", "LOW"), 2.0)
            if "abuse_scenarios" not in entry:
                entry["abuse_scenarios"] = entry.get("privacy_implications", [])
            return entry

        # 4. Return UNKNOWN when no reliable entry exists
        return self._build_unknown_entry(clean_id)

    def is_known(self, permission_identifier: str) -> bool:
        """
        Check whether the knowledge base contains a verified entry for the permission.
        """
        res = self.lookup(permission_identifier)
        return res.get("is_known", False)

    def _build_unknown_entry(self, identifier: str) -> Dict[str, Any]:
        """
        Construct a strict UNKNOWN entry.
        Adheres to requirement: never invent explanations for unknown permissions.
        """
        short = identifier.split(".")[-1] if identifier else "UNKNOWN"
        return {
            "permission": identifier,
            "category": "Unknown",
            "group": "Unknown",
            "short_name": short,
            "display_name": f"Unknown Permission ({identifier})",
            "description": "No reliable entry exists for this permission in the knowledge base.",
            "privacy_implications": [],
            "sensitive_data": [],
            "protection_level": "unknown",
            "platform_context": "This identifier is not part of the standard Android permission knowledge base or is a vendor/third-party custom permission.",
            "documentation_url": None,
            "risk_level": "UNKNOWN",
            "severity_score": 2.0,
            "abuse_scenarios": [],
            "remediation": "Audit the application source code or contact the vendor to verify why this unknown identifier is declared.",
            "explanation": "No reliable entry exists for this permission in the knowledge base. The application declares this identifier, but its behavior, protection level, and privacy implications cannot be reliably verified.",
            "is_known": False
        }

# Global singleton instance
permission_lookup_service = PermissionLookupService()
