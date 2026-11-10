"""
Unit and Integration Tests for Explainable Privacy Policy Analysis Module
Problem Statement: PS02 - Explainable Cybersecurity Application Privacy & Permission Analyzer

Tests Coverage:
1. Input validation (empty text, minimum length, maximum length, non-text).
2. Passage and paragraph splitting with verified character offsets and paragraph labels.
3. Accurate detection across the 14 required privacy domains.
4. Stance classification (EXPLICIT_DISCLOSURE, EXPLICIT_NEGATION, AMBIGUOUS, UNDETERMINED).
5. Exact evidence grounding: verifying quoted text matches full_text[start:end].
6. Epistemological safeguards: absence of disclosure is marked UNDETERMINED and not treated as proof.
7. Disclaimers: every domain explicitly notes that policy declarations do not prove runtime execution.
8. Fallback guarantee: deterministic execution runs reliably without any AI API key.
9. Database persistence & authenticated API endpoint (POST /api/v1/analyze/policy).
"""

import pytest
from unittest.mock import MagicMock
from sqlalchemy.orm import Session

from backend.policy_analyzer import (
    PolicyAnalyzer,
    PolicyAnalysisError,
    PRIVACY_DOMAINS
)
from backend.database import SessionLocal
from backend.models.user import User
from backend.models.analysis import Analysis
from backend.models.policy_excerpt import PolicyExcerpt
from backend.schemas.analysis import PolicyAnalysisRequest
from backend.routers.analysis import analyze_privacy_policy_post


SAMPLE_COMPREHENSIVE_POLICY = """
Privacy Policy for SecureMessenger

1. Information We Collect
We collect personal information such as your full name, email address, and phone number when you create an account.
We also automatically collect device information, including your operating system version, device model, and IP address.

2. Geolocation and Media Access
We collect your precise GPS location coordinates to enable nearby friend discovery.
We access your device camera to allow capturing photos and scanning QR codes.
We access your microphone to record voice messages that you choose to send.
We never read or access your contacts or address book.

3. Third Parties and Advertising
We share aggregated telemetry with third-party analytics vendors.
We do not sell your personal data to data brokers or advertising networks.
We may display non-personalized ads from time to time.

4. Data Retention, Storage, and Security
All user data is stored on secure cloud servers hosted in the United States using AES-256 encryption.
We retain personal information for as long as your account remains active.
You have the right to request deletion of your account and personal data at any time through the app settings.

5. Consent and International Transfers
By using our application, you consent to our data collection practices.
Your data may be transferred to international servers located outside your home country.
"""


def test_input_validation_empty_and_short_text():
    # Empty policy is accepted as optional and returns provided=False
    empty_result = PolicyAnalyzer.analyze_policy("")
    assert empty_result["provided"] is False
    assert empty_result["transparency_score"] == 0.0

    # Non-empty but too short text triggers validation error
    with pytest.raises(PolicyAnalysisError) as exc_info:
        PolicyAnalyzer.analyze_policy("Short")
    assert "too short" in str(exc_info.value).lower()


def test_passage_splitting_and_character_offsets():
    """Verify paragraph splitting accurately tracks indices, labels, and exact substring offsets."""
    text = "Paragraph One.\n\nParagraph Two is longer.\n\nParagraph Three."
    passages = PolicyAnalyzer.split_into_passages(text)
    assert len(passages) == 3

    assert passages[0]["paragraph_ref"] == "Paragraph 1"
    assert passages[0]["text"] == "Paragraph One."
    assert text[passages[0]["start_offset"]:passages[0]["end_offset"]] == "Paragraph One."

    assert passages[1]["paragraph_ref"] == "Paragraph 2"
    assert passages[1]["text"] == "Paragraph Two is longer."
    assert text[passages[1]["start_offset"]:passages[1]["end_offset"]] == "Paragraph Two is longer."

    assert passages[2]["paragraph_ref"] == "Paragraph 3"
    assert passages[2]["text"] == "Paragraph Three."
    assert text[passages[2]["start_offset"]:passages[2]["end_offset"]] == "Paragraph Three."


def test_14_privacy_domains_detected():
    """Verify that the comprehensive policy triggers evidence extraction across all 14 domains."""
    result = PolicyAnalyzer.analyze_policy(SAMPLE_COMPREHENSIVE_POLICY, app_name="SecureMessenger")

    domains = result["domains"]
    assert len(domains) == 14
    assert result["addressed_domains_count"] >= 13

    # Check key domains specifically
    assert domains["data_collection"]["status"] == "EXPLICIT_DISCLOSURE"
    assert domains["personal_information"]["status"] == "EXPLICIT_DISCLOSURE"
    assert domains["location_information"]["status"] == "EXPLICIT_DISCLOSURE"
    assert domains["camera_microphone"]["status"] == "EXPLICIT_DISCLOSURE"
    assert domains["device_information"]["status"] == "EXPLICIT_DISCLOSURE"
    assert domains["data_sharing_third_parties"]["status"] == "EXPLICIT_DISCLOSURE"
    assert domains["advertising_tracking"]["status"] in ("EXPLICIT_DISCLOSURE", "AMBIGUOUS")
    assert domains["data_storage"]["status"] == "EXPLICIT_DISCLOSURE"
    assert domains["data_retention"]["status"] == "EXPLICIT_DISCLOSURE"
    assert domains["data_deletion"]["status"] == "EXPLICIT_DISCLOSURE"
    assert domains["user_consent"]["status"] == "EXPLICIT_DISCLOSURE"
    assert domains["security_measures"]["status"] == "EXPLICIT_DISCLOSURE"
    assert domains["international_transfers"]["status"] == "EXPLICIT_DISCLOSURE"

    # Explicit denial on contacts
    assert domains["contacts"]["status"] == "EXPLICIT_NEGATION"


def test_exact_evidence_grounding_matches_source_text():
    """Ensure that every extracted excerpt strictly matches the original text slice at start_offset:end_offset."""
    result = PolicyAnalyzer.analyze_policy(SAMPLE_COMPREHENSIVE_POLICY)
    for domain_key, domain_data in result["domains"].items():
        for exc in domain_data["excerpts"]:
            start = exc["start_offset"]
            end = exc["end_offset"]
            expected_slice = SAMPLE_COMPREHENSIVE_POLICY[start:end]
            assert exc["exact_text"] == expected_slice, (
                f"Mismatch in domain {domain_key}: excerpt '{exc['exact_text']}' != slice '{expected_slice}'"
            )


def test_explicit_negation_stance():
    """Verify that assertive denials like 'we never access' are classified as EXPLICIT_NEGATION."""
    policy_negation = """
    Our Privacy Promise:
    We value your privacy above all else. We never access your contacts or read your phone book.
    We do not collect your location or track your movements.
    """
    result = PolicyAnalyzer.analyze_policy(policy_negation)
    domains = result["domains"]

    assert domains["contacts"]["status"] == "EXPLICIT_NEGATION"
    assert any(e["stance"] == "EXPLICIT_NEGATIVE" for e in domains["contacts"]["excerpts"])

    assert domains["location_information"]["status"] == "EXPLICIT_NEGATION"
    assert any(e["stance"] == "EXPLICIT_NEGATIVE" for e in domains["location_information"]["excerpts"])


def test_ambiguous_and_vague_qualifier_classification():
    """Verify that non-committal qualifiers like 'may collect from time to time' are flagged as AMBIGUOUS."""
    vague_policy = """
    Policy:
    We may collect certain personal information from time to time as we deem necessary.
    We might share certain data with partners at our discretion.
    """
    result = PolicyAnalyzer.analyze_policy(vague_policy)
    domains = result["domains"]

    # Must detect ambiguous stance
    pi_excerpts = domains["personal_information"]["excerpts"]
    assert any(e["stance"] == "AMBIGUOUS_VAGUE" for e in pi_excerpts)


def test_undetermined_domain_absence_not_treated_as_proof():
    """Verify unmentioned domains are marked UNDETERMINED with explicit disclaimers."""
    minimal_policy = """
    Simple Policy:
    We only collect your email address for account login purposes.
    """
    result = PolicyAnalyzer.analyze_policy(minimal_policy)
    domains = result["domains"]

    # Location was not mentioned at all
    assert domains["location_information"]["status"] == "UNDETERMINED"
    assert "not addressed" in domains["location_information"]["summary"].lower()
    assert "absence of a disclosure cannot be assumed to prove non-collection" in domains["location_information"]["summary"]

    # Every domain contains runtime execution disclaimer
    for d in domains.values():
        assert "does not prove actual runtime execution" in d["disclaimer"]


def test_deterministic_fallback_when_no_api_key():
    """Verify that without any AI API key, the analyzer functions deterministically with 100% reliability."""
    result = PolicyAnalyzer.analyze_policy(SAMPLE_COMPREHENSIVE_POLICY)
    assert result["provided"] is True
    assert result["ai_status"] == "deterministic_rules"
    assert result["transparency_score"] > 50.0
    assert len(result["overall_summary"]) > 10


def test_api_v1_analyze_policy_endpoint_and_database_persistence():
    """Test POST /api/v1/analyze/policy stores analysis and policy_excerpts for authenticated user."""
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.email == "policy_auditor@example.com").first()
        if not user:
            user = User(
                email="policy_auditor@example.com",
                full_name="Policy Auditor",
                password_hash="mock_hash_for_policy_test",
                role="user",
                is_active=True
            )
            db.add(user)
            db.commit()
            db.refresh(user)

        mock_request = MagicMock()
        mock_request.client.host = "127.0.0.1"

        req = PolicyAnalysisRequest(
            policy_text=SAMPLE_COMPREHENSIVE_POLICY,
            app_name="SecureMessenger Audit",
            analysis_id=None
        )

        response = analyze_privacy_policy_post(
            req=req,
            request=mock_request,
            current_user=user,
            db=db
        )

        assert response.analysis_id is not None
        assert response.app_name == "SecureMessenger Audit"
        assert response.addressed_domains_count >= 13
        assert response.transparency_score > 60.0
        assert len(response.domains) == 14

        # Verify relational database storage in analyses table
        saved_analysis = db.query(Analysis).filter(Analysis.id == response.analysis_id).first()
        assert saved_analysis is not None
        assert saved_analysis.user_id == user.id
        assert saved_analysis.app_name == "SecureMessenger Audit"

        # Verify excerpts stored in policy_excerpts table
        saved_excerpts = db.query(PolicyExcerpt).filter(PolicyExcerpt.analysis_id == response.analysis_id).all()
        assert len(saved_excerpts) > 0
        assert any(e.domain == "Personal Information" and e.excerpt_type == "disclosure" for e in saved_excerpts)
        assert any(e.domain == "Contacts" and e.excerpt_type == "negation" for e in saved_excerpts)
        assert any(e.paragraph_ref.startswith("Paragraph") for e in saved_excerpts)
        assert any(e.start_offset is not None and e.end_offset is not None for e in saved_excerpts)

    finally:
        db.close()
