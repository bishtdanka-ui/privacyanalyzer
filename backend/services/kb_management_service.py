"""
Knowledge Base Management Service for Administrator Review & Governance
Problem Statement: PS02 - Explainable Cybersecurity Application Privacy & Permission Analyzer

Capabilities:
- Retrieve curated permissions catalog for administrator review.
- Strict Pydantic JSON schema validation.
- Knowledge base version tracking and SHA-256 integrity hashing.
- Guard against publishing unvalidated permission explanations.
- Preserve developer documentation URLs and forensic references.
"""

import os
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from pydantic import ValidationError
from backend.config import settings
from backend.schemas.admin import PermissionKBEntrySchema, KBValidationResponse, KBMetadataResponse
from knowledge_base.lookup_service import permission_lookup_service, DEFAULT_KB_PATH

METADATA_FILE = DEFAULT_KB_PATH.parent / "metadata.json"


class KnowledgeBaseManagementService:
    """
    Manages knowledge base versioning, validation, and administrative publishing.
    """

    @classmethod
    def get_kb_path(cls) -> Path:
        return settings.KB_PATH if hasattr(settings, "KB_PATH") and settings.KB_PATH.exists() else DEFAULT_KB_PATH

    @classmethod
    def compute_checksum(cls) -> str:
        kb_path = cls.get_kb_path()
        if not kb_path.exists():
            return "none"
        with open(kb_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()[:16]

    @classmethod
    def get_metadata(cls) -> Dict[str, Any]:
        """
        Retrieves knowledge base governance metadata, version, and integrity checksum.
        """
        kb_path = cls.get_kb_path()
        checksum = cls.compute_checksum()
        entry_count = permission_lookup_service.get_entry_count()

        default_meta = {
            "version": "1.3.0",
            "last_modified": datetime.fromtimestamp(kb_path.stat().st_mtime, timezone.utc).isoformat() if kb_path.exists() else datetime.now(timezone.utc).isoformat(),
            "checksum": checksum,
            "total_entries": entry_count,
            "schema_status": "VALID",
            "categories": cls.get_unique_categories()
        }

        if METADATA_FILE.exists():
            try:
                with open(METADATA_FILE, "r", encoding="utf-8") as f:
                    stored = json.load(f)
                    default_meta["version"] = stored.get("version", "1.3.0")
                    default_meta["last_modified"] = stored.get("last_modified", default_meta["last_modified"])
            except Exception:
                pass

        return default_meta

    @classmethod
    def get_unique_categories(cls) -> List[str]:
        categories = set()
        for _, entry in permission_lookup_service._entries.items():
            if isinstance(entry, dict) and entry.get("category"):
                categories.add(entry["category"])
        return sorted(list(categories))

    @classmethod
    def list_entries(
        cls,
        search: Optional[str] = None,
        category: Optional[str] = None,
        risk_level: Optional[str] = None,
        protection_level: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Returns list of knowledge base permission entries with optional search and filtering.
        """
        results = []
        search_lower = search.lower().strip() if search else None
        cat_lower = category.lower().strip() if category else None
        risk_upper = risk_level.upper().strip() if risk_level else None
        prot_lower = protection_level.lower().strip() if protection_level else None

        for perm_id, entry in permission_lookup_service._entries.items():
            if not isinstance(entry, dict):
                continue

            # Filter by search string
            if search_lower:
                name_match = search_lower in perm_id.lower() or search_lower in entry.get("display_name", "").lower()
                desc_match = search_lower in entry.get("description", "").lower()
                if not (name_match or desc_match):
                    continue

            # Filter by category
            if cat_lower and entry.get("category", "").lower() != cat_lower:
                continue

            # Filter by risk level
            if risk_upper and entry.get("risk_level", "").upper() != risk_upper:
                continue

            # Filter by protection level
            if prot_lower and entry.get("protection_level", "").lower() != prot_lower:
                continue

            results.append(entry)

        return sorted(results, key=lambda x: x.get("permission", ""))

    @classmethod
    def validate_entry(cls, entry_data: Dict[str, Any]) -> KBValidationResponse:
        """
        Validates a candidate permission entry against the official JSON schema.
        Prevents unvalidated explanations from being published.
        """
        try:
            validated = PermissionKBEntrySchema(**entry_data)
            return KBValidationResponse(
                valid=True,
                permission=validated.permission,
                errors=[],
                message="Permission entry strictly conforms to knowledge base schema."
            )
        except ValidationError as e:
            errors = [f"{err['loc'][0]}: {err['msg']}" for err in e.errors()]
            return KBValidationResponse(
                valid=False,
                permission=entry_data.get("permission"),
                errors=errors,
                message="Schema validation failed. Check required fields and formatting."
            )
        except Exception as e:
            return KBValidationResponse(
                valid=False,
                permission=entry_data.get("permission"),
                errors=[str(e)],
                message="Unexpected validation error."
            )

    @classmethod
    def publish_entry(cls, entry_data: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Validates and atomically publishes a permission entry to the knowledge base file.
        Updates version metadata and reloads lookup service.
        """
        val_res = cls.validate_entry(entry_data)
        if not val_res.valid:
            return False, {"errors": val_res.errors, "message": val_res.message}

        kb_path = cls.get_kb_path()
        try:
            with open(kb_path, "r", encoding="utf-8") as f:
                kb_data = json.load(f)

            perm_id = entry_data["permission"].strip()
            # Clean and serialize data
            validated_obj = PermissionKBEntrySchema(**entry_data).model_dump()

            if isinstance(kb_data, list):
                replaced = False
                for idx, item in enumerate(kb_data):
                    if isinstance(item, dict) and item.get("permission") == perm_id:
                        kb_data[idx] = validated_obj
                        replaced = True
                        break
                if not replaced:
                    kb_data.append(validated_obj)
                total_count = len(kb_data)
            elif isinstance(kb_data, dict) and "permissions" in kb_data and isinstance(kb_data["permissions"], list):
                replaced = False
                for idx, item in enumerate(kb_data["permissions"]):
                    if isinstance(item, dict) and item.get("permission") == perm_id:
                        kb_data["permissions"][idx] = validated_obj
                        replaced = True
                        break
                if not replaced:
                    kb_data["permissions"].append(validated_obj)
                total_count = len(kb_data["permissions"])
            else:
                is_wrapped = isinstance(kb_data, dict) and "permissions" in kb_data and isinstance(kb_data["permissions"], dict)
                entries_dict = kb_data["permissions"] if is_wrapped else kb_data
                entries_dict[perm_id] = validated_obj
                total_count = len(entries_dict)

            # Atomic file save
            temp_path = kb_path.with_suffix(".tmp")
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(kb_data, f, indent=2)

            os.replace(temp_path, kb_path)

            # Update metadata version
            meta = cls.get_metadata()
            current_ver = meta.get("version", "1.3.0")
            parts = current_ver.split(".")
            if len(parts) == 3 and parts[2].isdigit():
                new_ver = f"{parts[0]}.{parts[1]}.{int(parts[2]) + 1}"
            else:
                new_ver = "1.3.1"

            new_meta = {
                "version": new_ver,
                "last_modified": datetime.now(timezone.utc).isoformat(),
                "total_entries": total_count
            }
            with open(METADATA_FILE, "w", encoding="utf-8") as f:
                json.dump(new_meta, f, indent=2)

            # Reload lookup service
            permission_lookup_service.load_knowledge_base()

            return True, {
                "message": f"Successfully published permission '{perm_id}'.",
                "permission": perm_id,
                "kb_version": new_ver,
                "entry": validated_obj
            }
        except Exception as e:
            return False, {"message": f"Failed to save entry to knowledge base: {str(e)}"}

