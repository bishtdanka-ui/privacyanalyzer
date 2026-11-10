"""
Explainable Permission Risk Analyzer
Problem Statement: PS02 - Explainable Cybersecurity Application Privacy & Permission Analyzer

Objectives:
- Classify permissions based on verified Android protection levels and sensitivity.
- Detail privacy impact: data accessed, device capabilities, sensitivity rationale.
- Explicitly define what the manifest declaration establishes vs. what it does NOT establish.
- Transparent rule-based risk levels (LOW, MEDIUM, HIGH, UNKNOWN).
- Strictly non-presumptive: never labels permissions as malicious; never assumes declaration proves actual data access.
"""

from typing import Dict, Any, Optional
from knowledge_base.lookup_service import permission_lookup_service

# Normalized Sensitivity Mapping
SENSITIVITY_TIERS = {
    # Critical data / high potential for financial or identity risk
    "CRITICAL": {
        "android.permission.SEND_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.REQUEST_INSTALL_PACKAGES"
    },
    # High sensitivity runtime data
    "HIGH": {
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_PHONE_STATE",
        "android.permission.CALL_PHONE",
        "android.permission.BODY_SENSORS",
        "android.permission.BLUETOOTH_SCAN",
        "android.permission.SYSTEM_ALERT_WINDOW"
    },
    # Medium sensitivity data
    "MEDIUM": {
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.ACTIVITY_RECOGNITION"
    },
    # Low sensitivity or utility permissions
    "LOW": {
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.INTERNET",
        "android.permission.BLUETOOTH",
        "android.permission.NFC",
        "android.permission.USE_BIOMETRIC"
    },
    # Negligible sensitivity
    "NEGLIGIBLE": {
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.ACCESS_WIFI_STATE",
        "android.permission.VIBRATE",
        "android.permission.WAKE_LOCK",
        "android.permission.RECEIVE_BOOT_COMPLETED"
    }
}


class PermissionRiskAnalyzer:
    """
    Evaluates Android permission risks using transparent, explainable criteria.
    Never asserts malicious intent; distinguishes potential exposure from actual execution.
    """

    @classmethod
    def classify_permission(cls, perm_name: str) -> Dict[str, Any]:
        """
        Retrieves knowledge base entry and classifies protection level and sensitivity tier.
        """
        clean_name = perm_name.strip()
        kb_entry = permission_lookup_service.lookup(clean_name)
        
        prot_level = kb_entry.get("protection_level", "unknown")
        canonical = kb_entry.get("permission", clean_name)

        # Determine sensitivity tier
        sensitivity = "UNKNOWN"
        if not kb_entry.get("is_known", False):
            sensitivity = "UNKNOWN"
        else:
            for tier, perms in SENSITIVITY_TIERS.items():
                if canonical in perms:
                    sensitivity = tier
                    break
            if sensitivity == "UNKNOWN":
                # Fallback based on protection level
                if prot_level == "dangerous":
                    sensitivity = "HIGH"
                elif prot_level in ("special", "signature/special"):
                    sensitivity = "HIGH"
                elif prot_level == "normal":
                    sensitivity = "LOW"

        return {
            "permission": canonical,
            "display_name": kb_entry.get("display_name", canonical.split(".")[-1]),
            "category": kb_entry.get("category", "Unknown"),
            "protection_level": prot_level,
            "sensitivity_tier": sensitivity,
            "is_known": kb_entry.get("is_known", False),
            "kb_entry": kb_entry
        }

    @classmethod
    def analyze_privacy_impact(cls, perm_name: str, kb_entry: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Produces detailed explainable breakdown of:
        1. Information that may be accessed
        2. Device capability involved
        3. Why the information is sensitive
        4. What the manifest declaration does and does NOT establish
        """
        if not kb_entry:
            kb_entry = permission_lookup_service.lookup(perm_name)

        clean_name = kb_entry.get("permission", perm_name)
        short_name = kb_entry.get("display_name", clean_name.split(".")[-1])
        is_known = kb_entry.get("is_known", False)

        if not is_known:
            return {
                "information_accessed": "Cannot be determined from the knowledge base.",
                "device_capability": "Proprietary, custom, or undocumented OS capability.",
                "sensitivity_rationale": "Unknown permission identifier cannot be verified against official Android specifications.",
                "declaration_boundaries": (
                    f"The application declares '{clean_name}'. This declaration alone does not establish "
                    f"whether the permission exists on the target OS, what capability it gates, or whether it has been granted."
                )
            }

        sens_data = kb_entry.get("sensitive_data", [])
        sens_data_str = ", ".join(sens_data) if sens_data else "Telemetry or system operational metadata"

        category = kb_entry.get("category", "General")
        prot_level = kb_entry.get("protection_level", "normal")

        # Device capability mapping
        capabilities = {
            "Camera": "Device camera sensor, image capture stream, and video hardware pipeline.",
            "Microphone": "Audio recording hardware, microphone sensor, and acoustic input stream.",
            "Location": "GPS receiver, GNSS chipset, cellular cell-tower IDs, and Wi-Fi scan cache.",
            "Contacts": "Device contacts database, address book provider, and account sync directories.",
            "Storage": "Shared external file system storage, media store volumes, and documents directory.",
            "Phone": "Telephony baseband modem, ongoing call management, and cellular state monitors.",
            "SMS": "SMS/MMS messaging subsystem, cellular transmission queue, and inbox provider.",
            "Bluetooth": "Bluetooth and Bluetooth Low Energy (BLE) radio hardware adapter.",
            "Sensors": "Physical hardware biometric sensors, heart rate monitor, or step sensor.",
            "System Overlay": "Window manager display compositor to draw views on top of other running apps.",
            "Network": "Network socket interface and internet protocol stack."
        }
        capability_involved = capabilities.get(category, f"{category} subsystem and associated hardware interfaces.")

        # Privacy impact explanation
        privacy_implications = kb_entry.get("privacy_implications", [])
        impact_str = " ".join(privacy_implications) if privacy_implications else kb_entry.get("description", "")

        # Epistemological boundary statement
        if prot_level == "dangerous":
            boundary = (
                f"Declaring '{clean_name}' in AndroidManifest.xml indicates the developer intended to request "
                f"access to {short_name.lower()}. This declaration alone does NOT prove that runtime authorization "
                f"was granted by the user, nor does it prove that data has been collected or transmitted."
            )
        elif prot_level == "normal":
            boundary = (
                f"Declaring '{clean_name}' allows automatic installation-time authorization by the operating system. "
                f"This declaration does NOT establish how frequently or for what specific data flows the capability is used."
            )
        else:
            boundary = (
                f"Declaring '{clean_name}' represents a special or privileged system capability. "
                f"Declaration alone does not demonstrate active execution or user authorization."
            )

        return {
            "information_accessed": sens_data_str,
            "device_capability": capability_involved,
            "sensitivity_rationale": impact_str,
            "declaration_boundaries": boundary
        }

    @classmethod
    def compute_risk_level(
        cls,
        protection_level: str,
        sensitivity_tier: str,
        purpose_alignment: str = "POTENTIALLY_EXPECTED",
        is_known: bool = True
    ) -> str:
        """
        Transparent rule-based risk level calculation:
        Returns LOW, MEDIUM, HIGH, or UNKNOWN.
        
        Rules:
        - UNKNOWN permission -> UNKNOWN.
        - Normal permissions (e.g. INTERNET, ACCESS_NETWORK_STATE) -> LOW.
        - Sensitive/Dangerous permissions:
          - If purpose aligns logically (POTENTIALLY_EXPECTED) -> MEDIUM (sensitive data, but justified).
          - If purpose mismatch (PURPOSE_MISMATCH / REQUIRES_REVIEW) -> HIGH (sensitive data without clear need).
          - If insufficient information -> HIGH.
        """
        if not is_known or protection_level == "unknown":
            return "UNKNOWN"

        # Normal permissions are benign utility permissions
        if protection_level == "normal":
            return "LOW"

        # Special permissions (e.g. overlays, install packages)
        if protection_level in ("special", "signature/special"):
            return "HIGH"

        # Dangerous runtime permissions
        if protection_level == "dangerous":
            if purpose_alignment == "POTENTIALLY_EXPECTED":
                # Data is sensitive, but consistent with expected app purpose
                if sensitivity_tier in ("CRITICAL", "HIGH"):
                    return "MEDIUM"
                return "LOW"
            elif purpose_alignment in ("PURPOSE_MISMATCH", "REQUIRES_REVIEW"):
                # Sensitive data requested without clear relevance to stated purpose
                return "HIGH"
            elif purpose_alignment == "INSUFFICIENT_INFORMATION":
                return "HIGH" if sensitivity_tier in ("CRITICAL", "HIGH") else "MEDIUM"

        return "LOW"

