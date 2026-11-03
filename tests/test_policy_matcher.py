from backend.services.privacy_policy_analyzer import PrivacyPolicyAnalyzer
from backend.services.purpose_matcher import PurposePermissionMatcher

def test_deceptive_contradiction_detection():
    # Privacy policy explicitly claims "We do not collect your location or SMS messages"
    policy_text = """
    Our Privacy Policy:
    We value your privacy. We do not collect your location coordinates or track your GPS.
    We never access your SMS messages or read your inbox.
    """
    manifest_permissions = [
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_SMS",
        "android.permission.INTERNET"
    ]

    analysis = PrivacyPolicyAnalyzer.analyze_policy_text(policy_text)
    discrepancies = PurposePermissionMatcher.match_permissions_with_policy(
        manifest_permissions,
        analysis
    )

    issue_types = [d["issue_type"] for d in discrepancies]
    assert "DECEPTIVE_CONTRADICTION" in issue_types
    # Both Location and SMS should trigger critical contradictions
    contradictions = [d for d in discrepancies if d["issue_type"] == "DECEPTIVE_CONTRADICTION"]
    assert len(contradictions) >= 2

def test_undisclosed_dangerous_permission():
    # Policy only mentions Camera
    policy_text = """
    We only access your Camera to take profile photos.
    """
    manifest_permissions = [
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS"  # Not mentioned at all!
    ]

    analysis = PrivacyPolicyAnalyzer.analyze_policy_text(policy_text)
    discrepancies = PurposePermissionMatcher.match_permissions_with_policy(
        manifest_permissions,
        analysis
    )

    undisclosed = [d for d in discrepancies if d["issue_type"] == "UNDISCLOSED_DANGEROUS_PERMISSION"]
    assert len(undisclosed) == 1
    assert undisclosed[0]["permission_name"] == "android.permission.READ_CONTACTS"
