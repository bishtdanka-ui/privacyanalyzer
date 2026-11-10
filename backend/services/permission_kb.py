import json
import logging
from typing import Dict, Any, List, Optional
from backend.config import settings
from knowledge_base.lookup_service import permission_lookup_service

logger = logging.getLogger(__name__)

FALLBACK_COMBO_RULES = [
    {
        "id": "surveillance_combo",
        "name": "Covert Audiovisual Surveillance & Exfiltration",
        "required_permissions": ["android.permission.RECORD_AUDIO", "android.permission.CAMERA", "android.permission.INTERNET"],
        "severity": "CRITICAL",
        "risk_penalty": 25,
        "explanation": "App has simultaneous access to the microphone, camera, and internet. This combination creates severe spyware capability to silently record surroundings, take photos, and immediately exfiltrate them to remote servers."
    },
    {
        "id": "location_tracking_combo",
        "name": "Persistent 24/7 Geolocation Tracking",
        "required_permissions": ["android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.INTERNET"],
        "severity": "CRITICAL",
        "risk_penalty": 25,
        "explanation": "App can track the user's high-precision location continuously even when the app is closed, and beam real-time coordinates over the internet. Characteristic of commercial stalkerware and invasive ad-trackers."
    },
    {
        "id": "banking_sms_interception",
        "name": "Financial OTP & 2FA Interception",
        "required_permissions": ["android.permission.READ_SMS", "android.permission.INTERNET"],
        "severity": "CRITICAL",
        "risk_penalty": 20,
        "explanation": "App can read incoming SMS messages and transmit data over the network. This pattern is commonly exploited by banking trojans to intercept one-time passwords (OTPs) and bypass two-factor authentication."
    },
    {
        "id": "social_graph_harvesting",
        "name": "Social Graph & Contact Scraping",
        "required_permissions": ["android.permission.READ_CONTACTS", "android.permission.INTERNET"],
        "severity": "HIGH",
        "risk_penalty": 15,
        "explanation": "App can harvest the user's full phone book and upload it to external databases. This exposes not only the device owner but also contacts, friends, and colleagues without their awareness."
    },
    {
        "id": "overlay_phishing",
        "name": "Deceptive Screen Overlay & Tapjacking",
        "required_permissions": ["android.permission.SYSTEM_ALERT_WINDOW", "android.permission.INTERNET"],
        "severity": "HIGH",
        "risk_penalty": 15,
        "explanation": "App can draw overlays on top of any other app while communicating with remote servers. Attackers use this to display counterfeit credential-prompt dialogs over authentic banking or email apps."
    },
    {
        "id": "file_tampering_ransomware",
        "name": "Shared Storage Exfiltration & Tampering",
        "required_permissions": ["android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.INTERNET"],
        "severity": "MEDIUM",
        "risk_penalty": 10,
        "explanation": "App can modify or wipe shared files and sync them remotely. Untrusted apps with this permission can inspect downloaded documents or stage ransomware-style payloads."
    },
    {
        "id": "reboot_persistence",
        "name": "Auto-Start Persistence & Surveillance",
        "required_permissions": ["android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.INTERNET"],
        "severity": "MEDIUM",
        "risk_penalty": 8,
        "explanation": "App registers to start running automatically as soon as the phone boots, enabling persistent unprompted background operations."
    }
]

class PermissionKnowledgeBase:
    _instance = None

    @classmethod
    def get_instance(cls) -> "PermissionKnowledgeBase":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def get_permission(self, perm_name: str) -> Dict[str, Any]:
        """
        Lookup permission metadata via the curated lookup service.
        """
        return permission_lookup_service.lookup(perm_name)

    def is_known(self, perm_name: str) -> bool:
        return permission_lookup_service.is_known(perm_name)

    def get_combo_rules(self) -> List[Dict[str, Any]]:
        # Check if custom combo rules exist in data/android_permissions_kb.json
        legacy_path = settings.KB_PATH.parent.parent / "data" / "android_permissions_kb.json"
        if legacy_path.exists():
            try:
                with open(legacy_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    rules = data.get("combo_rules")
                    if rules:
                        return rules
            except Exception:
                pass
        return FALLBACK_COMBO_RULES

permission_kb = PermissionKnowledgeBase.get_instance()
