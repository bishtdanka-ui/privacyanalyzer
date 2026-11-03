import re
from typing import Dict, Any, List, Optional
import defusedxml.ElementTree as ET

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

class ManifestParseError(Exception):
    pass

class ManifestParser:
    @staticmethod
    def _strip_ns(tag: str) -> str:
        return tag.split("}")[-1] if "}" in tag else tag

    @staticmethod
    def _get_android_attr(elem: ET.Element, attr_name: str) -> Optional[str]:
        # Try namespaced attribute
        val = elem.attrib.get(f"{ANDROID_NS}{attr_name}")
        if val is not None:
            return val
        # Try raw attribute without namespace
        val = elem.attrib.get(attr_name)
        if val is not None:
            return val
        # Try android: prefix string key
        return elem.attrib.get(f"android:{attr_name}")

    @classmethod
    def parse_xml_content(cls, xml_text: str) -> Dict[str, Any]:
        """
        Safely parse raw AndroidManifest.xml string using defusedxml.
        """
        if not xml_text or not xml_text.strip():
            raise ManifestParseError("Manifest content is empty.")

        try:
            root = ET.fromstring(xml_text.strip())
        except Exception as e:
            raise ManifestParseError(f"Malformed AndroidManifest.xml: {str(e)}")

        manifest_tag = cls._strip_ns(root.tag)
        if manifest_tag != "manifest":
            raise ManifestParseError(f"Root element must be <manifest>, found <{manifest_tag}>.")

        # Extract package & version info
        package_name = root.attrib.get("package", "unknown.package")
        version_code = cls._get_android_attr(root, "versionCode") or "1"
        version_name = cls._get_android_attr(root, "versionName") or "1.0.0"

        # Uses SDK
        min_sdk = None
        target_sdk = None
        uses_sdk_elem = root.find("uses-sdk")
        if uses_sdk_elem is not None:
            min_sdk = cls._get_android_attr(uses_sdk_elem, "minSdkVersion")
            target_sdk = cls._get_android_attr(uses_sdk_elem, "targetSdkVersion")

        # Fallback regex search for SDK if missing from element
        if not min_sdk:
            m = re.search(r'android:minSdkVersion=["\'](\d+)["\']', xml_text)
            if m:
                min_sdk = m.group(1)
        if not target_sdk:
            m = re.search(r'android:targetSdkVersion=["\'](\d+)["\']', xml_text)
            if m:
                target_sdk = m.group(1)

        # Extract permissions
        permissions = set()
        for elem in root.iter():
            tag = cls._strip_ns(elem.tag)
            if tag in ("uses-permission", "uses-permission-sdk-23", "permission"):
                name = cls._get_android_attr(elem, "name")
                if name:
                    permissions.add(name.strip())

        # Inspect <application>
        app_elem = root.find("application")
        app_label = package_name
        allow_backup = True
        debuggable = False
        exported_components = []
        all_components = []

        if app_elem is not None:
            raw_label = cls._get_android_attr(app_elem, "label")
            if raw_label:
                app_label = raw_label

            raw_backup = cls._get_android_attr(app_elem, "allowBackup")
            if raw_backup and raw_backup.lower() == "false":
                allow_backup = False

            raw_debug = cls._get_android_attr(app_elem, "debuggable")
            if raw_debug and raw_debug.lower() == "true":
                debuggable = True

            component_tags = ("activity", "service", "receiver", "provider")
            for comp in app_elem:
                comp_tag = cls._strip_ns(comp.tag)
                if comp_tag in component_tags:
                    comp_name = cls._get_android_attr(comp, "name") or "UnnamedComponent"
                    exported_val = cls._get_android_attr(comp, "exported")
                    permission_req = cls._get_android_attr(comp, "permission")
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

        # Analyze Target SDK Security Risks
        sdk_warnings = []
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
            sdk_warnings.append("CRITICAL: android:debuggable='true' allows unauthorized arbitrary code injection and memory dumping.")

        return {
            "app_name": app_label,
            "package_name": package_name,
            "version_code": version_code,
            "version_name": version_name,
            "min_sdk": min_sdk or "Not Specified",
            "target_sdk": target_sdk or "Not Specified",
            "permissions": sorted(list(permissions)),
            "allow_backup": allow_backup,
            "debuggable": debuggable,
            "components": all_components,
            "exported_components": exported_components,
            "exported_count": len(exported_components),
            "sdk_warnings": sdk_warnings
        }

