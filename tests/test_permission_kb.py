import pytest
import tempfile
import json
from pathlib import Path
from knowledge_base.lookup_service import PermissionLookupService, permission_lookup_service

REQUIRED_PERMISSIONS = [
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.SEND_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.NFC",
    "android.permission.BODY_SENSORS",
]

def test_all_required_permissions_exist():
    """Verify that every single required Android permission exists in the curated knowledge base."""
    for perm in REQUIRED_PERMISSIONS:
        entry = permission_lookup_service.lookup(perm)
        assert entry["is_known"] is True, f"Permission {perm} must be known in the KB."
        assert entry["permission"] == perm
        assert entry["category"]
        assert entry["display_name"]
        assert entry["description"]
        assert isinstance(entry["privacy_implications"], list)
        assert isinstance(entry["sensitive_data"], list)
        assert entry["protection_level"] in ("dangerous", "normal", "signature", "special", "signature/special")
        assert entry["platform_context"]
        assert entry["documentation_url"].startswith("https://developer.android.com/reference/android/Manifest.permission#")
        assert entry["risk_level"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE")
        assert "This application declares" in entry["explanation"]
        assert "alone does not prove" in entry["explanation"]

def test_lookup_by_short_name():
    """Verify lookup succeeds when using short names like 'CAMERA' instead of 'android.permission.CAMERA'."""
    entry = permission_lookup_service.lookup("CAMERA")
    assert entry["is_known"] is True
    assert entry["permission"] == "android.permission.CAMERA"
    assert entry["category"] == "Camera"

    entry_loc = permission_lookup_service.lookup("ACCESS_FINE_LOCATION")
    assert entry_loc["is_known"] is True
    assert entry_loc["permission"] == "android.permission.ACCESS_FINE_LOCATION"

def test_protection_level_classification():
    """Verify distinction between normal, dangerous, and special permissions."""
    # Dangerous runtime permissions
    camera = permission_lookup_service.lookup("CAMERA")
    assert camera["protection_level"] == "dangerous"
    assert camera["risk_level"] == "HIGH"

    record_audio = permission_lookup_service.lookup("RECORD_AUDIO")
    assert record_audio["protection_level"] == "dangerous"
    assert record_audio["risk_level"] == "HIGH"

    # Normal install-time permissions
    internet = permission_lookup_service.lookup("INTERNET")
    assert internet["protection_level"] == "normal"
    assert internet["risk_level"] == "LOW"

    network = permission_lookup_service.lookup("ACCESS_NETWORK_STATE")
    assert network["protection_level"] == "normal"
    assert network["risk_level"] == "NEGLIGIBLE"

    nfc = permission_lookup_service.lookup("NFC")
    assert nfc["protection_level"] == "normal"

    # Special / overlay permissions
    overlay = permission_lookup_service.lookup("SYSTEM_ALERT_WINDOW")
    assert overlay["protection_level"] == "special"
    assert overlay["risk_level"] == "CRITICAL"

def test_api_level_and_deprecation_platform_context():
    """Verify platform context documents modern Android API changes accurately."""
    # READ_EXTERNAL_STORAGE deprecated in Android 13 (API 33)
    legacy_storage = permission_lookup_service.lookup("READ_EXTERNAL_STORAGE")
    assert "Deprecated in Android 13" in legacy_storage["platform_context"] or "API level 33" in legacy_storage["platform_context"]

    # READ_MEDIA_IMAGES added in Android 13 (API 33)
    media_img = permission_lookup_service.lookup("READ_MEDIA_IMAGES")
    assert "Android 13" in media_img["platform_context"] or "API level 33" in media_img["platform_context"]

    # POST_NOTIFICATIONS added in Android 13 (API 33)
    notif = permission_lookup_service.lookup("POST_NOTIFICATIONS")
    assert "Android 13" in notif["platform_context"]

    # BLUETOOTH_SCAN added in Android 12 (API 31)
    bt_scan = permission_lookup_service.lookup("BLUETOOTH_SCAN")
    assert "Android 12" in bt_scan["platform_context"]

    # ACCESS_BACKGROUND_LOCATION added in Android 10 (API 29)
    bg_loc = permission_lookup_service.lookup("ACCESS_BACKGROUND_LOCATION")
    assert "Android 10" in bg_loc["platform_context"]

def test_unknown_permission_handling_never_invents_explanations():
    """Verify that unsupported/unknown permissions strictly return UNKNOWN without fabricated text."""
    unknown_id = "com.untrusted.vendor.permission.SECRET_EXPLOIT"
    entry = permission_lookup_service.lookup(unknown_id)

    assert entry["is_known"] is False
    assert entry["protection_level"] == "unknown"
    assert entry["risk_level"] == "UNKNOWN"
    assert entry["category"] == "Unknown"
    assert entry["documentation_url"] is None
    assert entry["privacy_implications"] == []
    assert entry["sensitive_data"] == []
    # Strict standardized explanation:
    assert "No reliable entry exists for this permission in the knowledge base." in entry["explanation"]
    assert "cannot be reliably verified" in entry["explanation"]

def test_knowledge_base_dynamic_expansion_without_engine_changes():
    """Verify that expanding the JSON knowledge base at runtime is automatically reflected."""
    custom_perm = {
        "permission": "android.permission.UWB_RANGING",
        "category": "Ultra-Wideband",
        "display_name": "Ultra-Wideband Ranging",
        "description": "Allows an app to perform ultra-wideband ranging.",
        "privacy_implications": ["Allows high-precision distance measurement to other UWB devices."],
        "sensitive_data": ["Precise Indoor Distance"],
        "protection_level": "dangerous",
        "platform_context": "Introduced in Android 12 (API level 31).",
        "documentation_url": "https://developer.android.com/reference/android/Manifest.permission#UWB_RANGING",
        "risk_level": "MEDIUM",
        "explanation": "This application declares ultra-wideband ranging. This declaration alone does not prove ranging is active."
    }

    with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False, encoding="utf-8") as tmp:
        json.dump({"android.permission.UWB_RANGING": custom_perm}, tmp)
        tmp_path = Path(tmp.name)

    try:
        custom_service = PermissionLookupService(kb_path=tmp_path)
        assert custom_service.get_entry_count() == 1
        
        entry = custom_service.lookup("UWB_RANGING")
        assert entry["is_known"] is True
        assert entry["category"] == "Ultra-Wideband"
        assert entry["display_name"] == "Ultra-Wideband Ranging"
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

def test_list_wrapped_knowledge_base_and_context_dependent_risk():
    """
    Verify support for list-wrapped schema format:
    {"version": "1.0", "permissions": [...]}
    with 'risk_level': 'CONTEXT_DEPENDENT' and omitted 'explanation'.
    """
    from backend.schemas.admin import PermissionKBEntrySchema

    payload = {
        "version": "1.0",
        "permissions": [
            {
                "permission": "android.permission.CAMERA",
                "category": "Camera",
                "display_name": "Camera Access",
                "description": "Allows an application to request access to the device camera.",
                "privacy_implications": [
                    "May expose images or video if access is granted and the camera is used."
                ],
                "sensitive_data": ["Images", "Video"],
                "protection_level": "dangerous",
                "risk_level": "CONTEXT_DEPENDENT",
                "platform_context": "Runtime permission requirements depend on Android version.",
                "documentation_url": "https://developer.android.com/reference/android/Manifest.permission#CAMERA"
            },
            {
                "permission": "android.permission.ACCESS_FINE_LOCATION",
                "category": "Location",
                "display_name": "Precise Location Access",
                "description": "Allows an application to request precise device location.",
                "privacy_implications": [
                    "May expose the user's precise location.",
                    "Location information can reveal movement patterns."
                ],
                "sensitive_data": ["Precise Location"],
                "protection_level": "dangerous",
                "risk_level": "CONTEXT_DEPENDENT",
                "platform_context": "Runtime authorization and background access restrictions apply.",
                "documentation_url": "https://developer.android.com/reference/android/Manifest.permission#ACCESS_FINE_LOCATION"
            }
        ]
    }

    # Verify Pydantic schema validation succeeds even when explanation is omitted
    for item in payload["permissions"]:
        validated = PermissionKBEntrySchema(**item)
        assert validated.risk_level == "CONTEXT_DEPENDENT"
        assert validated.explanation is not None
        assert "This application declares" in validated.explanation
        assert "alone does not prove" in validated.explanation

    with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False, encoding="utf-8") as tmp:
        json.dump(payload, tmp)
        tmp_path = Path(tmp.name)

    try:
        custom_service = PermissionLookupService(kb_path=tmp_path)
        assert custom_service.get_entry_count() == 2

        cam = custom_service.lookup("android.permission.CAMERA")
        assert cam["is_known"] is True
        assert cam["risk_level"] == "CONTEXT_DEPENDENT"
        assert cam["display_name"] == "Camera Access"
        assert "alone does not prove" in cam["explanation"]

        loc = custom_service.lookup("ACCESS_FINE_LOCATION")
        assert loc["is_known"] is True
        assert loc["risk_level"] == "CONTEXT_DEPENDENT"
        assert loc["display_name"] == "Precise Location Access"
        assert "alone does not prove" in loc["explanation"]
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


