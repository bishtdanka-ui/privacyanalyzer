"""
Secure AndroidManifest.xml Permission Extraction Engine
Problem Statement: PS02 - Explainable Cybersecurity Application Privacy & Permission Analyzer

Security Controls:
- Uses defusedxml to neutralize XML entity expansion (Billion Laughs), DTD injection, and XXE.
- Enforces strict upload payload size limits (MAX_MANIFEST_SIZE_BYTES = 5 MB).
- Validates text formatting and rejects compiled binary AXML or non-XML payloads safely.
- Never executes uploaded XML content; safe attribute and tag parsing only.
- Strict path sanitization on source_file references to prevent path traversal disclosures.
- Structural XPath-like source traceability (/manifest/uses-permission[n]) without line-number fabrication.
- Connected directly to the curated Android permission knowledge base.
"""

import os
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Union
from xml.etree.ElementTree import Element
import defusedxml.ElementTree as DefusedET
from defusedxml.common import DefusedXmlException, DTDForbidden, EntitiesForbidden

from knowledge_base.lookup_service import permission_lookup_service

# Constants
MAX_MANIFEST_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 Megabytes limit
ANDROID_NS: str = "http://schemas.android.com/apk/res/android"
ANDROID_NS_PREFIX: str = f"{{{ANDROID_NS}}}"

# Canonical Android manifest declarations
VALID_PERMISSION_TAGS: Set[str] = {
    "uses-permission",
    "uses-permission-sdk-23",
    "uses-permission-sdk-m"
}

KNOWN_MANIFEST_TAGS: Set[str] = {
    "manifest",
    "uses-permission",
    "uses-permission-sdk-23",
    "uses-permission-sdk-m",
    "permission",
    "permission-group",
    "permission-tree",
    "uses-feature",
    "uses-sdk",
    "application",
    "queries",
    "supports-screens",
    "compatible-screens",
    "supports-gl-texture",
    "instrumentation",
    "uses-configuration",
    "protected-broadcast",
    "original-package",
    "package-verifier"
}


class ManifestParseError(Exception):
    """Raised when XML is malformed, empty, or unparseable."""
    pass


class ManifestSecurityError(ManifestParseError):
    """Raised when a security threshold (e.g. entity expansion, size limit) is violated."""
    pass


class XMLSizeLimitExceededError(ManifestSecurityError):
    """Raised when the uploaded manifest exceeds maximum allowable size."""
    pass


class AndroidManifestParser:
    """
    Production-grade secure AndroidManifest.xml parser powered by defusedxml.
    Extracts permission declarations with XPath-like structural source references,
    detects duplicates, flags unsupported/unknown declarations, and correlates
    directly with the curated Android permission knowledge base.
    """

    @staticmethod
    def strip_ns(tag: str) -> str:
        """Strip XML namespace prefix from tag name."""
        return tag.split("}")[-1] if "}" in tag else tag

    @classmethod
    def get_android_attr(cls, elem: Element, attr_name: str) -> Optional[str]:
        """
        Safely retrieve an Android-namespaced attribute with robust fallback
        for varying namespace declarations, prefixes, and unqualified forms.
        """
        # 1. Standard namespaced attribute {http://schemas.android.com/apk/res/android}name
        val = elem.attrib.get(f"{ANDROID_NS_PREFIX}{attr_name}")
        if val is not None:
            return val

        # 2. android: prefix string key
        val = elem.attrib.get(f"android:{attr_name}")
        if val is not None:
            return val

        # 3. Raw attribute without namespace
        val = elem.attrib.get(attr_name)
        if val is not None:
            return val

        # 4. Fallback search for any attribute key matching the suffix
        for key, value in elem.attrib.items():
            if key.endswith(f"}}{attr_name}") or key.endswith(f":{attr_name}"):
                return value

        return None

    @classmethod
    def validate_and_prepare_content(
        cls,
        content: Union[str, bytes],
        source_name: str = "AndroidManifest.xml"
    ) -> tuple[str, str]:
        """
        Enforces upload size limits, safe text decoding, and path sanitization.
        Returns (decoded_xml_text, sanitized_source_filename).
        """
        # Strict filename sanitization
        safe_source_file = Path(source_name).name or "AndroidManifest.xml"
        if not safe_source_file.endswith(".xml"):
            safe_source_file = f"{safe_source_file}.xml"

        # Check payload size limits
        raw_size = len(content) if isinstance(content, (str, bytes)) else 0
        if raw_size > MAX_MANIFEST_SIZE_BYTES:
            raise XMLSizeLimitExceededError(
                f"Manifest file size ({raw_size} bytes) exceeds maximum limit of "
                f"{MAX_MANIFEST_SIZE_BYTES} bytes (5 MB)."
            )

        if raw_size == 0:
            raise ManifestParseError("Manifest content is empty.")

        # Decode if bytes
        if isinstance(content, bytes):
            # Check for binary compiled AXML magic header (0x00080003 in little endian: \x03\x00\x08\x00)
            if content.startswith(b"\x03\x00\x08\x00") or content.startswith(b"\x00\x00\x08\x00"):
                raise ManifestParseError(
                    "Compiled binary AndroidManifest.xml detected. This analyzer requires "
                    "readable, decoded XML text (e.g., extracted via apktool or aapt2)."
                )

            # Check for excessive null bytes indicative of binary payloads
            if content.count(b"\x00") > 10:
                raise ManifestParseError(
                    "Binary or non-text data detected in manifest file. Upload readable XML text."
                )

            # Safe multi-encoding decode
            decoded: Optional[str] = None
            for enc in ("utf-8", "utf-8-sig", "latin-1"):
                try:
                    decoded = content.decode(enc)
                    break
                except UnicodeDecodeError:
                    continue

            if decoded is None:
                raise ManifestParseError("Unable to decode manifest file with valid text encoding (UTF-8/Latin-1).")
            xml_text = decoded
        else:
            xml_text = content

        stripped = xml_text.strip()
        if not stripped:
            raise ManifestParseError("Manifest content is empty.")

        return stripped, safe_source_file

    @classmethod
    def parse(
        cls,
        content: Union[str, bytes],
        source_name: str = "AndroidManifest.xml"
    ) -> Dict[str, Any]:
        """
        Securely parse AndroidManifest.xml and extract permissions, SDK versions,
        components, and knowledge base explainability records.
        """
        xml_text, safe_source_file = cls.validate_and_prepare_content(content, source_name)

        # Secure XML parsing via defusedxml
        try:
            root = DefusedET.fromstring(xml_text)
        except (DTDForbidden, EntitiesForbidden, DefusedXmlException) as sec_err:
            raise ManifestSecurityError(
                f"Security Violation: Malicious XML entity or DTD expansion detected ({type(sec_err).__name__})."
            ) from sec_err
        except Exception as parse_err:
            raise ManifestParseError(f"Malformed AndroidManifest.xml: {str(parse_err)}") from parse_err

        # Validate root element
        root_tag = cls.strip_ns(root.tag)
        if root_tag != "manifest":
            raise ManifestParseError(f"Root element must be <manifest>, found <{root_tag}>.")

        # Extract package name and version metadata
        package_name = root.attrib.get("package") or cls.get_android_attr(root, "package") or "unknown.package"
        version_code = cls.get_android_attr(root, "versionCode") or "1"
        version_name = cls.get_android_attr(root, "versionName") or "1.0.0"

        # Extract uses-sdk metadata
        min_sdk: Optional[str] = None
        target_sdk: Optional[str] = None
        max_sdk_platform: Optional[str] = None

        for child in root:
            if cls.strip_ns(child.tag) == "uses-sdk":
                min_sdk = cls.get_android_attr(child, "minSdkVersion")
                target_sdk = cls.get_android_attr(child, "targetSdkVersion")
                max_sdk_platform = cls.get_android_attr(child, "maxSdkVersion")
                break

        # Regex fallback for SDK versions if not found on element
        if not min_sdk:
            m = re.search(r'android:minSdkVersion=["\']([^"\']+)["\']', xml_text)
            if m:
                min_sdk = m.group(1)
        if not target_sdk:
            m = re.search(r'android:targetSdkVersion=["\']([^"\']+)["\']', xml_text)
            if m:
                target_sdk = m.group(1)
        if not max_sdk_platform:
            m = re.search(r'android:maxSdkVersion=["\']([^"\']+)["\']', xml_text)
            if m:
                max_sdk_platform = m.group(1)

        # Extraction tracking structures
        tag_counters: Dict[str, int] = {
            "uses-permission": 0,
            "uses-permission-sdk-23": 0,
            "uses-permission-sdk-m": 0,
            "permission": 0
        }
        manifest_child_counters: Dict[str, int] = {}
        
        seen_permissions: Set[str] = set()
        duplicate_count: int = 0
        permission_records: List[Dict[str, Any]] = []
        raw_permission_names: List[str] = []
        unsupported_declarations: List[Dict[str, Any]] = []

        dangerous_count: int = 0
        normal_count: int = 0
        special_count: int = 0
        unknown_count: int = 0

        # Scan direct children of <manifest> for permissions and unsupported declarations
        for child in root:
            tag = cls.strip_ns(child.tag)
            manifest_child_counters[tag] = manifest_child_counters.get(tag, 0) + 1
            structural_path = f"/manifest/{tag}[{manifest_child_counters[tag]}]"

            # Check for unsupported or unknown tags under manifest
            if tag not in KNOWN_MANIFEST_TAGS:
                unsupported_declarations.append({
                    "tag": child.tag,
                    "clean_tag": tag,
                    "source_reference": structural_path,
                    "reason": f"Unrecognized manifest declaration <{tag}>.",
                    "attributes": dict(child.attrib)
                })

            # Check for permission declarations
            if tag in VALID_PERMISSION_TAGS or tag == "permission":
                tag_counters[tag] = tag_counters.get(tag, 0) + 1
                source_reference = f"/manifest/{tag}[{tag_counters[tag]}]"

                perm_name = cls.get_android_attr(child, "name")
                if not perm_name or not perm_name.strip():
                    unsupported_declarations.append({
                        "tag": child.tag,
                        "clean_tag": tag,
                        "source_reference": source_reference,
                        "reason": f"Permission declaration <{tag}> missing required 'android:name' attribute."
                    })
                    continue

                perm_name = perm_name.strip()
                raw_permission_names.append(perm_name)

                # Check maxSdkVersion on permission declaration
                raw_max_sdk = cls.get_android_attr(child, "maxSdkVersion")
                max_sdk_int: Optional[int] = None
                if raw_max_sdk:
                    try:
                        max_sdk_int = int(raw_max_sdk)
                    except ValueError:
                        max_sdk_int = None

                # Detect duplicate declarations
                is_duplicate = perm_name in seen_permissions
                if is_duplicate:
                    duplicate_count += 1
                else:
                    seen_permissions.add(perm_name)

                # Connect to Curated Knowledge Base
                kb_entry = permission_lookup_service.lookup(perm_name)
                prot_level = kb_entry.get("protection_level", "unknown")

                if prot_level == "dangerous":
                    dangerous_count += 1
                elif prot_level in ("special", "signature/special"):
                    special_count += 1
                elif prot_level == "normal":
                    normal_count += 1
                else:
                    unknown_count += 1

                record = {
                    "permission_name": perm_name,
                    "declaration_type": tag,
                    "max_sdk_version": max_sdk_int,
                    "source_file": safe_source_file,
                    "source_reference": source_reference,
                    "is_duplicate": is_duplicate,
                    "category": kb_entry.get("category", "Unknown"),
                    "protection_level": prot_level,
                    "risk_level": kb_entry.get("risk_level", "UNKNOWN"),
                    "explanation": kb_entry.get("explanation"),
                    "privacy_implications": kb_entry.get("privacy_implications", []),
                    "sensitive_data": kb_entry.get("sensitive_data", []),
                    "documentation_url": kb_entry.get("documentation_url"),
                    "platform_context": kb_entry.get("platform_context"),
                    "is_known": kb_entry.get("is_known", False)
                }
                permission_records.append(record)

        # Inspect <application> metadata and components
        app_elem = root.find("application")
        app_label = package_name
        allow_backup = True
        debuggable = False
        exported_components: List[Dict[str, Any]] = []
        all_components: List[Dict[str, Any]] = []

        if app_elem is not None:
            raw_label = cls.get_android_attr(app_elem, "label")
            if raw_label:
                app_label = raw_label

            raw_backup = cls.get_android_attr(app_elem, "allowBackup")
            if raw_backup and raw_backup.lower() == "false":
                allow_backup = False

            raw_debug = cls.get_android_attr(app_elem, "debuggable")
            if raw_debug and raw_debug.lower() == "true":
                debuggable = True

            component_tags = ("activity", "service", "receiver", "provider")
            for comp in app_elem:
                comp_tag = cls.strip_ns(comp.tag)
                if comp_tag in component_tags:
                    comp_name = cls.get_android_attr(comp, "name") or "UnnamedComponent"
                    exported_val = cls.get_android_attr(comp, "exported")
                    permission_req = cls.get_android_attr(comp, "permission")
                    has_intent_filter = comp.find("intent-filter") is not None

                    is_exported = False
                    if exported_val is not None:
                        is_exported = exported_val.lower() == "true"
                    elif has_intent_filter:
                        # Prior to Android 12, components with intent-filters default to exported=true
                        is_exported = True

                    comp_info = {
                        "type": comp_tag,
                        "name": comp_name,
                        "exported": is_exported,
                        "permission": permission_req,
                        "has_intent_filter": has_intent_filter
                    }
                    all_components.append(comp_info)
                    if is_exported:
                        exported_components.append(comp_info)

        # Analyze Target SDK & Environment Warnings
        sdk_warnings: List[str] = []
        try:
            target_int = int(target_sdk) if target_sdk else 30
            if target_int < 23:
                sdk_warnings.append("CRITICAL: Target SDK < 23 does not support runtime permission prompts (all permissions auto-granted at install).")
            elif target_int < 28:
                sdk_warnings.append("HIGH: Target SDK < 28 permits cleartext unencrypted HTTP traffic by default.")
            elif target_int < 31:
                sdk_warnings.append("MEDIUM: Target SDK < 31 does not enforce explicit android:exported attributes on components with intent-filters.")
            elif target_int < 33:
                sdk_warnings.append("LOW: Target SDK < 33 does not require granular media permissions (uses broad READ_EXTERNAL_STORAGE).")
        except ValueError:
            pass

        if debuggable:
            sdk_warnings.append("CRITICAL: android:debuggable='true' allows unauthorized arbitrary code execution and memory dumping.")

        # Distinct permissions for backward-compatible engine consumption
        distinct_permissions = sorted(list(seen_permissions))

        return {
            "app_name": app_label,
            "package_name": package_name,
            "version_code": version_code,
            "version_name": version_name,
            "min_sdk": min_sdk or "Not Specified",
            "target_sdk": target_sdk or "Not Specified",
            "max_sdk_version": max_sdk_platform,
            "permissions": distinct_permissions,
            "permission_records": permission_records,
            "raw_permission_names": raw_permission_names,
            "total_permissions": len(permission_records),
            "unique_permissions": len(seen_permissions),
            "duplicate_count": duplicate_count,
            "dangerous_count": dangerous_count,
            "normal_count": normal_count,
            "special_count": special_count,
            "unknown_count": unknown_count,
            "unsupported_declarations": unsupported_declarations,
            "allow_backup": allow_backup,
            "debuggable": debuggable,
            "components": all_components,
            "exported_components": exported_components,
            "exported_count": len(exported_components),
            "sdk_warnings": sdk_warnings,
            "source_file": safe_source_file
        }

    # Backward compatibility alias
    parse_xml_content = parse


# Module-level aliases
ManifestParser = AndroidManifestParser

