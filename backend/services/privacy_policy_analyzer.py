import re
from typing import Dict, Any, List

DOMAIN_PATTERNS = {
    "Camera": {
        "keywords": ["camera", "photo", "photograph", "picture", "video recording", "lens", "snapshot"],
        "regex": r"\b(camera|photo|photographs?|pictures?|video recording|snapshot)\b"
    },
    "Microphone": {
        "keywords": ["microphone", "audio", "voice", "sound", "record audio", "speech", "ambient"],
        "regex": r"\b(microphone|audio|voice|speech|record audio|ambient sound)\b"
    },
    "Location": {
        "keywords": ["location", "gps", "geographic", "coordinates", "places", "coarse location", "precise location", "geofence"],
        "regex": r"\b(locations?|gps|geographic|coordinates?|places?|geofence)\b"
    },
    "Contacts": {
        "keywords": ["contacts", "address book", "phone book", "friends list", "connections"],
        "regex": r"\b(contacts?|address book|phone ?book)\b"
    },
    "SMS": {
        "keywords": ["sms", "text message", "otp", "one-time password", "verification code"],
        "regex": r"\b(sms|text messages?|otps?|verification codes?)\b"
    },
    "Storage": {
        "keywords": ["storage", "files", "sd card", "documents", "downloads", "media files"],
        "regex": r"\b(storage|files?|sd card|documents?|downloads?)\b"
    },
    "Phone State": {
        "keywords": ["phone state", "device status", "call logs?", "phone numbers?", "imei", "device identifier"],
        "regex": r"\b(phone state|device status|call logs?|phone numbers?|imei|device identifiers?)\b"
    },
    "Sensors": {
        "keywords": ["body sensor", "heart rate", "fitness", "activity recognition", "steps", "biometric"],
        "regex": r"\b(sensors?|heart rate|fitness|activity recognition|steps?|biometrics?)\b"
    }
}

class PrivacyPolicyAnalyzer:
    @classmethod
    def analyze_policy_text(cls, policy_text: str) -> Dict[str, Any]:
        """
        Extract declared data practices, explicit negations, and disclosure quality.
        """
        if not policy_text or not policy_text.strip():
            return {
                "provided": False,
                "transparency_score": 0.0,
                "disclosed_domains": {},
                "negated_domains": {},
                "third_party_sharing": False,
                "data_retention_mentioned": False,
                "summary": "No privacy policy was supplied for cross-verification."
            }

        text_lower = policy_text.lower()
        sentences = re.split(r'[.\n\r]+', text_lower)
        sentences = [s.strip() for s in sentences if len(s.strip()) > 5]

        disclosed_domains: Dict[str, List[str]] = {}
        negated_domains: Dict[str, List[str]] = {}

        # Negation patterns: e.g. "we do not collect location", "we never access your contacts"
        negation_prefix = r"(do not|don't|never|cannot|will not|won't|does not|no)\s+(collect|access|store|share|track|record|read)"

        for domain, info in DOMAIN_PATTERNS.items():
            pattern = info["regex"]
            found_disclosures = []
            found_negations = []

            for s in sentences:
                if re.search(pattern, s):
                    # Check if sentence contains negation
                    if re.search(negation_prefix, s):
                        found_negations.append(s)
                    else:
                        found_disclosures.append(s)

            if found_disclosures:
                disclosed_domains[domain] = found_disclosures[:3]
            if found_negations:
                negated_domains[domain] = found_negations[:2]

        # Check third-party sharing
        tp_patterns = [r"third[- ]part(y|ies)", r"advertis(ing|ers)", r"data brokers?", r"share with partners"]
        tp_shared = any(re.search(p, text_lower) for p in tp_patterns)

        # Check retention
        retention_patterns = [r"retention", r"retain your data", r"store.*period", r"delete your data"]
        retention_mentioned = any(re.search(p, text_lower) for p in retention_patterns)

        # Calculate a transparency score out of 100
        score = 20.0  # Base for having a policy
        score += min(len(disclosed_domains) * 12.0, 50.0)
        if tp_shared:
            score += 15.0
        if retention_mentioned:
            score += 15.0

        transparency_score = round(min(score, 100.0), 1)

        return {
            "provided": True,
            "transparency_score": transparency_score,
            "word_count": len(policy_text.split()),
            "disclosed_domains": disclosed_domains,
            "negated_domains": negated_domains,
            "third_party_sharing": tp_shared,
            "data_retention_mentioned": retention_mentioned,
            "summary": f"Policy analyzed across {len(disclosed_domains)} declared domains with {len(negated_domains)} explicit privacy assurances."
        }

