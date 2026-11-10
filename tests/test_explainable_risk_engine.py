"""
Unit and Integration Tests for Explainable Permission Risk Analysis Engine
Problem Statement: PS02 - Explainable Cybersecurity Application Privacy & Permission Analyzer

Tests Coverage:
1. Permission classification (verified protection level and sensitivity tier).
2. Privacy impact analysis (data accessed, device capability, sensitivity rationale, declaration boundaries).
3. Purpose comparison:
   - Calculator requesting Camera -> PURPOSE_MISMATCH + review question.
   - Navigation requesting Location -> POTENTIALLY_EXPECTED + navigation explanation.
   - Messaging requesting Contacts -> POTENTIALLY_EXPECTED + contact discovery explanation.
   - Internet permission -> POTENTIALLY_EXPECTED + LOW risk (never treated as automatically dangerous).
4. Finding categories (POTENTIALLY_EXPECTED, REQUIRES_REVIEW, PURPOSE_MISMATCH, UNKNOWN_PERMISSION, INSUFFICIENT_INFORMATION).
5. Transparent rule-based risk levels (LOW, MEDIUM, HIGH, UNKNOWN).
6. Non-presumptive boundaries: declarations alone do not prove actual collection.
7. Exact explainability schema compliance:
   permission, risk_level, finding_category, reason, privacy_implication,
   purpose_comparison, review_question, evidence_source, source_reference, confidence.
8. Policy comparison (EXPLICIT_DISCLOSURE, UNCLEAR_DISCLOSURE, EXPLICIT_CONTRADICTION, NO_MATCHING_EVIDENCE).
9. Database persistence (saving in comparison_findings and updating permissions).
10. API endpoints:
   - POST /api/v1/analyze/compare
   - GET /api/v1/analyses/{analysis_id}/findings
"""

import pytest
from unittest.mock import MagicMock
from sqlalchemy.orm import Session

from backend.risk_analyzer import PermissionRiskAnalyzer
from backend.comparison_service import ComparisonService
from backend.explainability_service import ExplainabilityService
from backend.policy_analyzer import PolicyAnalyzer
from backend.database import SessionLocal
from backend.models.user import User
from backend.models.analysis import Analysis
from backend.models.permission import Permission
from backend.models.comparison_finding import ComparisonFinding
from backend.schemas.analysis import PurposeComparisonRequest
from backend.routers.analysis import compare_purpose_post, get_analyses_findings


def test_permission_classification_and_sensitivity_tiers():
    """Verify correct protection level and sensitivity classification."""
    cam = PermissionRiskAnalyzer.classify_permission("android.permission.CAMERA")
    assert cam["protection_level"] == "dangerous"
    assert cam["sensitivity_tier"] == "HIGH"
    assert cam["is_known"] is True

    net = PermissionRiskAnalyzer.classify_permission("android.permission.INTERNET")
    assert net["protection_level"] == "normal"
    assert net["sensitivity_tier"] == "LOW"
    assert net["is_known"] is True

    unknown = PermissionRiskAnalyzer.classify_permission("com.custom.secret.PRIVILEGE")
    assert unknown["protection_level"] == "unknown"
    assert unknown["sensitivity_tier"] == "UNKNOWN"
    assert unknown["is_known"] is False


def test_privacy_impact_and_declaration_boundaries():
    """Verify that privacy impact explicitly notes that manifest declarations do not prove runtime execution."""
    impact = PermissionRiskAnalyzer.analyze_privacy_impact("android.permission.RECORD_AUDIO")
    assert "microphone" in impact["device_capability"].lower()
    assert "audio" in impact["information_accessed"].lower() or "sound" in impact["information_accessed"].lower()
    assert "declaration alone does not prove" in impact["declaration_boundaries"].lower()


def test_calculator_requesting_camera_purpose_mismatch():
    """Verify that a calculator app requesting camera raises a PURPOSE_MISMATCH and review question."""
    comp = ComparisonService.compare_permission_with_purpose(
        perm_canonical="android.permission.CAMERA",
        prot_level="dangerous",
        sensitivity_tier="HIGH",
        app_name="Simple Calculator",
        app_purpose="Basic arithmetic calculations and unit conversions."
    )
    assert comp["finding_category"] == "PURPOSE_MISMATCH"
    assert "does not clearly explain" in comp["purpose_comparison"]
    assert "calculator" in comp["review_question"].lower()
    assert "camera" in comp["review_question"].lower()

    # Risk level check
    risk = PermissionRiskAnalyzer.compute_risk_level("dangerous", "HIGH", comp["finding_category"])
    assert risk == "HIGH"


def test_navigation_requesting_location_potentially_expected():
    """Verify that a navigation app requesting location is POTENTIALLY_EXPECTED and justified."""
    comp = ComparisonService.compare_permission_with_purpose(
        perm_canonical="android.permission.ACCESS_FINE_LOCATION",
        prot_level="dangerous",
        sensitivity_tier="HIGH",
        app_name="CityNav GPS",
        app_purpose="Turn-by-turn navigation and live traffic routing."
    )
    assert comp["finding_category"] == "POTENTIALLY_EXPECTED"
    assert "turn-by-turn navigation" in comp["purpose_comparison"].lower() or "map positioning" in comp["purpose_comparison"].lower()
    assert comp["review_question"] is None

    # Risk level check: sensitive data, but justified -> MEDIUM
    risk = PermissionRiskAnalyzer.compute_risk_level("dangerous", "HIGH", comp["finding_category"])
    assert risk == "MEDIUM"


def test_messaging_requesting_contacts_potentially_expected():
    """Verify that a messaging app requesting contacts is recognized as potentially expected for friend discovery."""
    comp = ComparisonService.compare_permission_with_purpose(
        perm_canonical="android.permission.READ_CONTACTS",
        prot_level="dangerous",
        sensitivity_tier="HIGH",
        app_name="SwiftChat",
        app_purpose="Instant messaging, chat channels, and audio voice messages."
    )
    assert comp["finding_category"] == "POTENTIALLY_EXPECTED"
    assert "contact" in comp["purpose_comparison"].lower()


def test_internet_permission_not_treated_as_automatically_dangerous():
    """Verify that INTERNET permission is classified as LOW risk and POTENTIALLY_EXPECTED."""
    comp = ComparisonService.compare_permission_with_purpose(
        perm_canonical="android.permission.INTERNET",
        prot_level="normal",
        sensitivity_tier="LOW",
        app_name="Simple Calculator",
        app_purpose="Basic arithmetic calculator."
    )
    assert comp["finding_category"] == "POTENTIALLY_EXPECTED"

    risk = PermissionRiskAnalyzer.compute_risk_level("normal", "LOW", comp["finding_category"])
    assert risk == "LOW"


def test_unknown_permission_and_insufficient_information():
    """Verify handling of unknown permissions and empty application purposes."""
    unknown_comp = ComparisonService.compare_permission_with_purpose(
        perm_canonical="com.oem.vendor.TELEMETRY_INTERNAL",
        prot_level="unknown",
        sensitivity_tier="UNKNOWN",
        app_name="App",
        app_purpose="General app",
        is_known=False
    )
    assert unknown_comp["finding_category"] == "UNKNOWN_PERMISSION"

    no_purpose_comp = ComparisonService.compare_permission_with_purpose(
        perm_canonical="android.permission.CAMERA",
        prot_level="dangerous",
        sensitivity_tier="HIGH",
        app_name="",
        app_purpose=""
    )
    assert no_purpose_comp["finding_category"] == "INSUFFICIENT_INFORMATION"


def test_policy_comparison_distinctions():
    """Verify policy comparison distinguishes disclosure, unclear disclosure, contradiction, and missing evidence."""
    policy_text = """
    We explicitly collect your camera photos for profile customization.
    We may collect certain device telemetry from time to time as we deem necessary.
    We never collect or track your location coordinates.
    """
    policy_findings = PolicyAnalyzer.analyze_policy(policy_text)

    # 1. Explicit Disclosure
    cam_comp = ComparisonService.compare_permission_with_policy("android.permission.CAMERA", policy_findings)
    assert cam_comp["policy_status"] == "EXPLICIT_DISCLOSURE"
    assert cam_comp["disclosed_in_policy"] is True

    # 2. Explicit Contradiction
    loc_comp = ComparisonService.compare_permission_with_policy("android.permission.ACCESS_FINE_LOCATION", policy_findings)
    assert loc_comp["policy_status"] == "EXPLICIT_CONTRADICTION"

    # 3. Unclear Disclosure
    dev_comp = ComparisonService.compare_permission_with_policy("android.permission.READ_PHONE_STATE", policy_findings)
    assert dev_comp["policy_status"] == "UNCLEAR_DISCLOSURE"

    # 4. No Matching Evidence (contacts was never mentioned)
    contact_comp = ComparisonService.compare_permission_with_policy("android.permission.READ_CONTACTS", policy_findings)
    assert contact_comp["policy_status"] == "NO_MATCHING_EVIDENCE"


def test_exact_explainability_schema_compliance():
    """Verify that every finding record strictly adheres to the requested JSON schema."""
    finding = ExplainabilityService.analyze_permission(
        perm_identifier="android.permission.CAMERA",
        app_name="Math Solver",
        app_purpose="Solves algebra and arithmetic equations.",
        source_reference="/manifest/uses-permission[1]"
    )

    required_keys = [
        "permission",
        "risk_level",
        "finding_category",
        "reason",
        "privacy_implication",
        "purpose_comparison",
        "review_question",
        "evidence_source",
        "source_reference",
        "confidence"
    ]
    for key in required_keys:
        assert key in finding, f"Key '{key}' missing from explainability finding record."

    assert finding["permission"] == "android.permission.CAMERA"
    assert finding["risk_level"] in ("LOW", "MEDIUM", "HIGH", "UNKNOWN")
    assert finding["finding_category"] in ("POTENTIALLY_EXPECTED", "REQUIRES_REVIEW", "PURPOSE_MISMATCH", "UNKNOWN_PERMISSION", "INSUFFICIENT_INFORMATION")
    assert finding["confidence"] == "RULE_BASED"
    assert finding["evidence_source"] == "AndroidManifest.xml"
    assert finding["source_reference"] == "/manifest/uses-permission[1]"
    assert "camera" in finding["reason"].lower()


def test_api_v1_analyze_compare_and_get_findings_persistence():
    """Test POST /api/v1/analyze/compare and GET /api/v1/analyses/{analysis_id}/findings."""
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.email == "explainability_tester@example.com").first()
        if not user:
            user = User(
                email="explainability_tester@example.com",
                full_name="Explainability Tester",
                password_hash="mock_hash_for_test",
                role="user",
                is_active=True
            )
            db.add(user)
            db.commit()
            db.refresh(user)

        mock_request = MagicMock()
        mock_request.client.host = "127.0.0.1"

        req = PurposeComparisonRequest(
            app_name="Simple Calculator",
            app_purpose="Basic arithmetic calculations.",
            permissions=[
                "android.permission.CAMERA",
                "android.permission.INTERNET",
                "android.permission.VIBRATE"
            ]
        )

        # 1. Call POST /api/v1/analyze/compare
        response = compare_purpose_post(
            req=req,
            request=mock_request,
            current_user=user,
            db=db
        )

        assert response.analysis_id is not None
        assert response.app_name == "Simple Calculator"
        assert response.total_permissions == 3
        assert len(response.findings) == 3

        cam_finding = next(f for f in response.findings if f.permission == "android.permission.CAMERA")
        assert cam_finding.finding_category == "PURPOSE_MISMATCH"
        assert cam_finding.risk_level == "HIGH"
        assert "calculator" in cam_finding.review_question.lower()

        vibe_finding = next(f for f in response.findings if f.permission == "android.permission.VIBRATE")
        assert vibe_finding.finding_category == "POTENTIALLY_EXPECTED"
        assert vibe_finding.risk_level == "LOW"

        # 2. Verify database records in comparison_findings
        db_findings = db.query(ComparisonFinding).filter(
            ComparisonFinding.analysis_id == response.analysis_id,
            ComparisonFinding.finding_type == "PURPOSE_COMPARISON"
        ).all()
        assert len(db_findings) == 3

        # 3. Call GET /api/v1/analyses/{analysis_id}/findings
        get_response = get_analyses_findings(
            analysis_id=response.analysis_id,
            current_user=user,
            db=db
        )
        assert get_response.analysis_id == response.analysis_id
        assert len(get_response.findings) == 3
        assert any(f.permission == "android.permission.CAMERA" and f.finding_category == "PURPOSE_MISMATCH" for f in get_response.findings)

    finally:
        db.close()

