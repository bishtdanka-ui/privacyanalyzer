"""
Permission and Purpose Comparison Service
Problem Statement: PS02 - Explainable Cybersecurity Application Privacy & Permission Analyzer

Objectives:
- Compare declared Android permissions against the user-supplied application purpose.
- Categorize findings into:
  * POTENTIALLY_EXPECTED
  * REQUIRES_REVIEW
  * PURPOSE_MISMATCH
  * UNKNOWN_PERMISSION
  * INSUFFICIENT_INFORMATION
- Compare declared permissions against privacy policy findings:
  * EXPLICIT_DISCLOSURE
  * UNCLEAR_DISCLOSURE
  * EXPLICIT_CONTRADICTION
  * NO_MATCHING_EVIDENCE
- Generate non-presumptive, evidence-grounded review questions.
"""

import re
from typing import Dict, Any, List, Optional, Tuple
from backend.policy_analyzer import PolicyAnalyzer

# Category intent signatures
APP_PURPOSE_PROFILES = {
    "CALCULATOR": {
        "keywords": ["calculator", "calc", "arithmetic", "math", "converter", "unit conversion"],
        "expected_permissions": {
            "android.permission.VIBRATE",
            "android.permission.WAKE_LOCK"
        },
        "explain_expected": {
            "android.permission.VIBRATE": "Haptic feedback for keypad button presses.",
            "android.permission.WAKE_LOCK": "Prevent screen dimming during prolonged numerical calculation sessions."
        }
    },
    "NAVIGATION": {
        "keywords": ["navigation", "navigate", "map", "maps", "gps", "directions", "turn-by-turn", "transit", "route", "routing", "commute", "rideshare", "delivery"],
        "expected_permissions": {
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.VIBRATE",
            "android.permission.POST_NOTIFICATIONS"
        },
        "explain_expected": {
            "android.permission.ACCESS_FINE_LOCATION": "Location access is consistent with turn-by-turn navigation and map positioning functionality.",
            "android.permission.ACCESS_COARSE_LOCATION": "Approximate location for initial regional map loading and city-level routing.",
            "android.permission.ACCESS_BACKGROUND_LOCATION": "Provides turn-by-turn voice prompts when the navigation screen is backgrounded.",
            "android.permission.INTERNET": "Live map tile retrieval, real-time traffic updates, and cloud routing calculations."
        }
    },
    "MESSAGING": {
        "keywords": ["messaging", "messenger", "chat", "chatting", "sms", "instant message", "texting", "social", "communication", "talk"],
        "expected_permissions": {
            "android.permission.READ_CONTACTS",
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.POST_NOTIFICATIONS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_MEDIA_VIDEO",
            "android.permission.VIBRATE"
        },
        "explain_expected": {
            "android.permission.READ_CONTACTS": "Contact access may be consistent with user discovery, contact matching, and address book synchronization in messaging applications.",
            "android.permission.CAMERA": "Allows capturing photos and video clips to share directly within chat conversations.",
            "android.permission.RECORD_AUDIO": "Allows recording and sending voice messages or participating in VoIP calls.",
            "android.permission.POST_NOTIFICATIONS": "Alerts the user to incoming text messages and voice call requests."
        }
    },
    "CAMERA_PHOTO": {
        "keywords": ["camera", "photography", "photos", "photo editor", "picture", "selfie", "scan", "scanner", "qr code"],
        "expected_permissions": {
            "android.permission.CAMERA",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_MEDIA_VIDEO",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_EXTERNAL_STORAGE"
        },
        "explain_expected": {
            "android.permission.CAMERA": "Optical image stream capture for photography and scanning operations.",
            "android.permission.READ_MEDIA_IMAGES": "Importing and editing existing photo gallery assets."
        }
    },
    "AUDIO_MUSIC": {
        "keywords": ["audio", "music", "podcast", "radio", "player", "recorder", "sound recorder", "voice recorder"],
        "expected_permissions": {
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_MEDIA_AUDIO",
            "android.permission.INTERNET",
            "android.permission.POST_NOTIFICATIONS"
        },
        "explain_expected": {
            "android.permission.RECORD_AUDIO": "Capturing microphone input for audio recording functionality.",
            "android.permission.READ_MEDIA_AUDIO": "Playback of stored music tracks and downloaded audio episodes."
        }
    },
    "HEALTH_FITNESS": {
        "keywords": ["health", "fitness", "workout", "running", "jogging", "step counter", "heart rate", "biometric", "exercise"],
        "expected_permissions": {
            "android.permission.ACTIVITY_RECOGNITION",
            "android.permission.BODY_SENSORS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION"
        },
        "explain_expected": {
            "android.permission.BODY_SENSORS": "Reading physiological sensors (e.g. heart rate monitors) during exercise.",
            "android.permission.ACTIVITY_RECOGNITION": "Automatic step counting and workout modality recognition.",
            "android.permission.ACCESS_FINE_LOCATION": "Outdoor running and cycling GPS route tracking."
        }
    }
}


class ComparisonService:
    """
    Performs explainable cross-comparisons between:
    1. Declared Android permissions and user-supplied application purpose.
    2. Declared Android permissions and extracted privacy policy findings.
    """

    @classmethod
    def detect_purpose_profile(cls, app_name: Optional[str], app_purpose: Optional[str]) -> Tuple[Optional[str], str]:
        """
        Analyzes app name and purpose text to identify matching application domain profile.
        Returns (profile_key, display_name).
        """
        combined = f"{app_name or ''} {app_purpose or ''}".lower()
        if not combined.strip():
            return None, "General Application"

        for key, profile in APP_PURPOSE_PROFILES.items():
            for kw in profile["keywords"]:
                if re.search(r"\b" + re.escape(kw) + r"\b", combined):
                    return key, key.replace("_", " ").title()

        return None, "General Application"

    @classmethod
    def compare_permission_with_purpose(
        cls,
        perm_canonical: str,
        prot_level: str,
        sensitivity_tier: str,
        app_name: Optional[str],
        app_purpose: Optional[str],
        is_known: bool = True
    ) -> Dict[str, Any]:
        """
        Evaluates whether a permission declaration aligns with the supplied application purpose.
        Returns:
        - finding_category (POTENTIALLY_EXPECTED, REQUIRES_REVIEW, PURPOSE_MISMATCH, UNKNOWN_PERMISSION, INSUFFICIENT_INFORMATION)
        - purpose_comparison (detailed explanation of alignment or lack thereof)
        - review_question (actionable review question for the analyst/user)
        """
        short_name = perm_canonical.split(".")[-1]

        if not is_known:
            return {
                "finding_category": "UNKNOWN_PERMISSION",
                "purpose_comparison": "Unknown or proprietary permission identifier cannot be correlated with application purpose.",
                "review_question": f"Is this custom permission '{short_name}' strictly necessary for core application functionality?"
            }

        # Check if purpose was supplied
        if not app_purpose or not app_purpose.strip():
            # If no purpose supplied, but app name might suggest something, check or declare insufficient info
            if not app_name or not app_name.strip():
                return {
                    "finding_category": "INSUFFICIENT_INFORMATION",
                    "purpose_comparison": "No application purpose was supplied to evaluate whether this permission aligns with expected functionality.",
                    "review_question": f"What specific user-facing feature in this application relies on {short_name}?"
                }

        profile_key, profile_display = cls.detect_purpose_profile(app_name, app_purpose)

        # 1. Normal protection level permissions (benign utilities)
        if prot_level == "normal":
            if perm_canonical == "android.permission.INTERNET":
                return {
                    "finding_category": "POTENTIALLY_EXPECTED",
                    "purpose_comparison": "Standard internet communication permission for network requests, cloud sync, or telemetry.",
                    "review_question": None
                }
            return {
                "finding_category": "POTENTIALLY_EXPECTED",
                "purpose_comparison": f"Standard install-time utility permission ({short_name}) commonly utilized for basic OS integration.",
                "review_question": None
            }

        # 2. Known Profile Evaluation
        if profile_key:
            profile = APP_PURPOSE_PROFILES[profile_key]
            if perm_canonical in profile["expected_permissions"]:
                explanation = profile["explain_expected"].get(
                    perm_canonical,
                    f"{short_name} is consistent with standard functionality for {profile_display} applications."
                )
                return {
                    "finding_category": "POTENTIALLY_EXPECTED",
                    "purpose_comparison": explanation,
                    "review_question": None
                }
            else:
                # Sensitive permission not part of expected profile
                purpose_desc = f"'{app_purpose.strip()}'" if app_purpose else f"{profile_display} functionality"
                return {
                    "finding_category": "PURPOSE_MISMATCH",
                    "purpose_comparison": (
                        f"The supplied application purpose ({purpose_desc}) does not clearly explain why "
                        f"{short_name.lower()} access would be required."
                    ),
                    "review_question": f"Why does this {profile_display.lower()} application require {short_name} access?"
                }

        # 3. No specific profile matched (General application with provided purpose)
        # Search purpose text directly for mention of permission keywords
        keywords_map = {
            "CAMERA": ["camera", "photo", "picture", "scan", "qr"],
            "RECORD_AUDIO": ["audio", "microphone", "mic", "voice", "sound", "record"],
            "ACCESS_FINE_LOCATION": ["location", "gps", "map", "places", "nearby", "coordinates"],
            "ACCESS_COARSE_LOCATION": ["location", "gps", "map", "city", "regional"],
            "READ_CONTACTS": ["contacts", "address book", "friends", "invite"],
            "READ_SMS": ["sms", "otp", "text message", "verification"],
            "SEND_SMS": ["sms", "text message", "send sms"],
            "READ_EXTERNAL_STORAGE": ["files", "storage", "documents", "photos", "downloads"],
            "READ_MEDIA_IMAGES": ["photos", "images", "pictures", "gallery"],
            "BODY_SENSORS": ["sensors", "heart rate", "fitness", "biometrics"]
        }

        matched_kws = keywords_map.get(short_name, [])
        purpose_lower = (app_purpose or "").lower()
        if any(kw in purpose_lower for kw in matched_kws):
            return {
                "finding_category": "POTENTIALLY_EXPECTED",
                "purpose_comparison": f"The declared purpose explicitly references features associated with {short_name.lower()}.",
                "review_question": None
            }

        # Sensitive runtime permission without matching context in general app
        purpose_label = f"'{app_purpose.strip()}'" if (app_purpose and app_purpose.strip()) else "General Application"
        return {
            "finding_category": "REQUIRES_REVIEW",
            "purpose_comparison": (
                f"The application purpose ({purpose_label}) does not provide sufficient context "
                f"to determine whether {short_name.lower()} is necessary for primary workflows."
            ),
            "review_question": f"Does the application provide a feature that genuinely necessitates {short_name}?"
        }

    @classmethod
    def compare_permission_with_policy(
        cls,
        perm_canonical: str,
        policy_findings: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Cross-verifies a permission declaration against extracted privacy policy domains.
        Returns:
        - policy_status (EXPLICIT_DISCLOSURE, UNCLEAR_DISCLOSURE, EXPLICIT_CONTRADICTION, NO_MATCHING_EVIDENCE)
        - policy_explanation (grounded summary of policy alignment)
        """
        if not policy_findings or not policy_findings.get("provided", False):
            return {
                "policy_status": "NO_MATCHING_EVIDENCE",
                "policy_explanation": "No privacy policy was supplied for cross-verification.",
                "disclosed_in_policy": False
            }

        short_name = perm_canonical.split(".")[-1]

        # Map permission to 14 policy domain keys
        perm_to_domain_key = {
            "CAMERA": "camera_microphone",
            "RECORD_AUDIO": "camera_microphone",
            "ACCESS_FINE_LOCATION": "location_information",
            "ACCESS_COARSE_LOCATION": "location_information",
            "ACCESS_BACKGROUND_LOCATION": "location_information",
            "READ_CONTACTS": "contacts",
            "WRITE_CONTACTS": "contacts",
            "READ_SMS": "data_collection",
            "RECEIVE_SMS": "data_collection",
            "READ_EXTERNAL_STORAGE": "data_storage",
            "WRITE_EXTERNAL_STORAGE": "data_storage",
            "READ_MEDIA_IMAGES": "camera_microphone",
            "READ_MEDIA_VIDEO": "camera_microphone",
            "READ_PHONE_STATE": "device_information",
            "BODY_SENSORS": "personal_information",
            "ACTIVITY_RECOGNITION": "personal_information",
            "INTERNET": "data_collection",
            "ACCESS_NETWORK_STATE": "device_information"
        }

        domain_key = perm_to_domain_key.get(short_name)
        if not domain_key:
            return {
                "policy_status": "NO_MATCHING_EVIDENCE",
                "policy_explanation": f"No specific privacy policy domain maps to {short_name}.",
                "disclosed_in_policy": False
            }

        domains = policy_findings.get("domains", {})
        domain_info = domains.get(domain_key)

        if not domain_info:
            return {
                "policy_status": "NO_MATCHING_EVIDENCE",
                "policy_explanation": f"The privacy policy does not address {domain_key.replace('_', ' ')}.",
                "disclosed_in_policy": False
            }

        domain_status = domain_info.get("status")

        if domain_status == "EXPLICIT_NEGATION":
            return {
                "policy_status": "EXPLICIT_CONTRADICTION",
                "policy_explanation": (
                    f"Direct Contradiction: The privacy policy explicitly asserts that it does not collect or access "
                    f"{domain_info['display_name'].lower()}, but AndroidManifest.xml requests '{perm_canonical}'."
                ),
                "disclosed_in_policy": False
            }
        elif domain_status == "EXPLICIT_DISCLOSURE":
            return {
                "policy_status": "EXPLICIT_DISCLOSURE",
                "policy_explanation": f"The privacy policy explicitly discloses practices regarding {domain_info['display_name'].lower()}.",
                "disclosed_in_policy": True
            }
        elif domain_status == "AMBIGUOUS":
            return {
                "policy_status": "UNCLEAR_DISCLOSURE",
                "policy_explanation": (
                    f"The privacy policy mentions {domain_info['display_name'].lower()} using vague or non-committal qualifiers."
                ),
                "disclosed_in_policy": False
            }
        else:
            return {
                "policy_status": "NO_MATCHING_EVIDENCE",
                "policy_explanation": f"The privacy policy contains no disclosure regarding {domain_info['display_name'].lower()}.",
                "disclosed_in_policy": False
            }

