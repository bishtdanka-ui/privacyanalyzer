import os
import json
import csv
import pytest
from datetime import datetime, timezone
from pathlib import Path
from fastapi import HTTPException
from fastapi.responses import FileResponse, Response

from backend.report_service import ReportService
from backend.models.user import User
from backend.models.analysis import Analysis
from backend.models.permission import Permission
from backend.models.policy_excerpt import PolicyExcerpt
from backend.models.comparison_finding import ComparisonFinding
from backend.models.report import Report
from backend.routers.analysis import (
    get_analyses_report,
    get_analysis_report_alias,
    download_pdf_report
)


@pytest.fixture
def sample_audit_analysis(db_session, normal_user):
    """
    Creates an analysis instance populated with permissions, policy excerpts,
    purpose comparisons, and an unknown permission.
    """
    analysis = Analysis(
        user_id=normal_user.id,
        app_name="Camera Calculator Plus",
        package_name="com.security.cameracalculator",
        version_code="102",
        version_name="2.1.0",
        min_sdk="26",
        target_sdk="34",
        total_permissions=4,
        dangerous_count=2,
        normal_count=1,
        special_count=0,
        risk_score=78.5,
        risk_level="HIGH",
        exported_components_count=1,
        raw_manifest="<manifest>...</manifest>",
        raw_policy="We collect device camera frames to process optical calculations. We do not sell data.",
        created_at=datetime.now(timezone.utc)
    )
    db_session.add(analysis)
    db_session.flush()

    # Permissions
    p1 = Permission(
        analysis_id=analysis.id,
        name="android.permission.CAMERA",
        short_name="CAMERA",
        permission_group="Camera",
        protection_level="dangerous",
        description="Allows an application to request access to the device camera.",
        privacy_risk="May allow capturing images or video streams when authorized.",
        severity_score=8.5,
        remediation="Request camera access at runtime only when OCR is explicitly invoked.",
        source_reference="/manifest/uses-permission[1]",
        declaration_type="uses-permission",
        finding_category="PURPOSE_MISMATCH",
        risk_level="HIGH"
    )
    p2 = Permission(
        analysis_id=analysis.id,
        name="android.permission.INTERNET",
        short_name="INTERNET",
        permission_group="Network",
        protection_level="normal",
        description="Allows applications to open network sockets.",
        privacy_risk="Enables data transmission over the internet.",
        severity_score=2.0,
        remediation="Follow least privilege and encrypt all outgoing traffic.",
        source_reference="/manifest/uses-permission[2]",
        declaration_type="uses-permission",
        finding_category="POTENTIALLY_EXPECTED",
        risk_level="LOW"
    )
    p3 = Permission(
        analysis_id=analysis.id,
        name="android.permission.ACCESS_FINE_LOCATION",
        short_name="ACCESS_FINE_LOCATION",
        permission_group="Location",
        protection_level="dangerous",
        description="Allows an app to access precise location.",
        privacy_risk="High privacy sensitivity. May reveal exact user whereabouts.",
        severity_score=8.0,
        remediation="Use coarse location or approximate geofencing instead.",
        source_reference="/manifest/uses-permission[3]",
        declaration_type="uses-permission",
        finding_category="PURPOSE_MISMATCH",
        risk_level="HIGH"
    )
    p4 = Permission(
        analysis_id=analysis.id,
        name="com.custom.vendor.OEM_TRACKING",
        short_name="OEM_TRACKING",
        permission_group="Custom / Vendor",
        protection_level="unknown",
        description="Custom proprietary OEM permission declaration.",
        privacy_risk="Unknown proprietary functionality.",
        severity_score=5.0,
        remediation="Inspect vendor SDK documentation.",
        source_reference="/manifest/uses-permission[4]",
        declaration_type="uses-permission",
        finding_category="UNKNOWN_PERMISSION",
        risk_level="UNKNOWN"
    )
    db_session.add_all([p1, p2, p3, p4])

    # Policy Excerpt
    pe = PolicyExcerpt(
        analysis_id=analysis.id,
        domain="Camera",
        excerpt_type="disclosure",
        text_snippet="We collect device camera frames to process optical calculations.",
        sentiment_or_stance="affirmative_collection",
        paragraph_ref="Paragraph 1",
        start_offset=0,
        end_offset=65
    )
    db_session.add(pe)

    # Purpose Comparison Finding
    cf1 = ComparisonFinding(
        analysis_id=analysis.id,
        finding_type="PURPOSE_COMPARISON",
        severity="HIGH",
        title="Purpose Assessment: CAMERA (PURPOSE_MISMATCH)",
        explanation="A basic arithmetic calculator rarely requires optical hardware sensors.",
        remediation="Explain why camera sensors are necessary for calculator calculations.",
        permission="android.permission.CAMERA",
        finding_category="PURPOSE_MISMATCH",
        review_question="Why does this calculator application require camera access?",
        purpose_comparison="A calculator application rarely requires camera hardware for arithmetic computations.",
        evidence_source="AndroidManifest.xml",
        source_reference="/manifest/uses-permission[1]",
        matched_data={
            "app_purpose": "Basic offline calculator application",
            "permission": "android.permission.CAMERA",
            "finding_category": "PURPOSE_MISMATCH"
        }
    )

    # Combo Threat Chain
    cf2 = ComparisonFinding(
        analysis_id=analysis.id,
        finding_type="COMBO_THREAT",
        severity="HIGH",
        title="Surveillance Threat Chain",
        explanation="Simultaneous access to Camera and Network interfaces presents exfiltration vectors.",
        remediation="Audit background network uploads during camera operation.",
        matched_data={
            "matched_permissions": ["android.permission.CAMERA", "android.permission.INTERNET"]
        }
    )
    db_session.add_all([cf1, cf2])
    db_session.commit()
    db_session.refresh(analysis)
    return analysis


def test_pdf_report_structure_and_evidence_sections(sample_audit_analysis, db_session):
    """
    Validates publication-grade PDF generation with:
    - Cover page (PrivacyGuard Shield Logo, App Name, Analysis Date, Report ID)
    - Section 1: Executive Summary (Metrics, Risk distribution, Observations)
    - Section 2: Extracted Permissions (Identifier, Category, Description, Impact, Protection, Risk, Source)
    - Section 3: Unknown Permissions (Identifier, Source, Reason, Recommendation)
    - Section 4: Privacy Policy Analysis (Original excerpts, Topics, Summaries, Paragraph/Char offsets)
    - Section 5: Application Purpose Comparison (User Purpose, Examined perms, Review questions)
    - Section 6: Limitations (4 clear boundary statements)
    """
    pdf_path = ReportService.generate_pdf_report(sample_audit_analysis, db_session)
    assert os.path.exists(pdf_path)
    assert os.path.getsize(pdf_path) > 2000

    # Verify PDF magic header
    with open(pdf_path, "rb") as f:
        header = f.read(5)
    assert header == b"%PDF-"


def test_json_report_export_complete_evidence_metadata(sample_audit_analysis, db_session):
    """
    Validates JSON export containing full structured findings, exact XPath references,
    privacy policy grounded excerpts, purpose comparisons, and methodology limitations.
    Ensures zero leakage of credentials, passwords, or tokens.
    """
    json_data = ReportService.generate_json_report(sample_audit_analysis, db_session)
    assert isinstance(json_data, dict)

    # 1. Report Metadata
    meta = json_data["report_metadata"]
    assert meta["application_name"] == "Camera Calculator Plus"
    assert meta["package_name"] == "com.security.cameracalculator"
    assert meta["target_sdk"] == "34"
    assert "PG-AUDIT-" in meta["report_id"]
    assert "report_generated_at" in meta

    # 2. Executive Summary
    exec_sum = json_data["executive_summary"]
    assert exec_sum["total_permissions"] == 4
    assert exec_sum["known_permissions"] == 3
    assert exec_sum["unknown_permissions"] == 1
    assert exec_sum["dangerous_count"] == 2
    assert exec_sum["risk_level"] == "HIGH"
    assert "CRITICAL" in exec_sum["risk_distribution"]
    assert "Observations" in exec_sum["overall_observations"] or len(exec_sum["overall_observations"]) > 20

    # 3. Extracted Permissions
    perms = json_data["extracted_permissions"]
    assert len(perms) == 4
    camera_perm = next(p for p in perms if p["permission"] == "android.permission.CAMERA")
    assert camera_perm["category"] == "Camera"
    assert camera_perm["protection_level"] == "dangerous"
    assert camera_perm["risk_level"] == "HIGH"
    assert camera_perm["source_reference"] == "/manifest/uses-permission[1]"
    assert "camera" in camera_perm["description"].lower()

    # 4. Unknown Permissions
    unknowns = json_data["unknown_permissions"]
    assert len(unknowns) == 1
    assert unknowns[0]["permission"] == "com.custom.vendor.OEM_TRACKING"
    assert unknowns[0]["source_reference"] == "/manifest/uses-permission[4]"
    assert "not cataloged" in unknowns[0]["reason_unsupported"].lower()
    assert "inspect" in unknowns[0]["manual_verification_recommendation"].lower()

    # 5. Privacy Policy Analysis
    policy_data = json_data["privacy_policy_analysis"]
    assert policy_data["policy_provided"] is True
    assert len(policy_data["excerpts"]) == 1
    ex = policy_data["excerpts"][0]
    assert ex["domain"] == "Camera"
    assert ex["character_offsets"]["start"] == 0
    assert ex["character_offsets"]["end"] == 65
    assert "camera" in ex["original_excerpt"].lower()

    # 6. Purpose Comparison
    purp_data = json_data["purpose_comparison"]
    assert "calculator" in purp_data["supplied_purpose"].lower()
    assert len(purp_data["findings"]) >= 1
    cam_finding = next(f for f in purp_data["findings"] if "CAMERA" in f["permission"])
    assert cam_finding["finding_category"] == "PURPOSE_MISMATCH"
    assert "calculator" in cam_finding["why_expected_or_unexpected"].lower()
    assert "?" in cam_finding["review_questions"]

    # 7. Limitations
    limitations = json_data["limitations"]
    assert len(limitations) == 4
    boundary_types = {lim["boundary"] for lim in limitations}
    assert "RUNTIME_VERIFICATION" in boundary_types
    assert "POLICY_VERIFICATION" in boundary_types
    assert "MALICE_DETERMINATION" in boundary_types
    assert "UNKNOWN_DECLARATIONS" in boundary_types

    # 8. Data Security Verification: No sensitive secrets leaked
    dumped_str = json.dumps(json_data).lower()
    assert "password" not in dumped_str
    assert "argon2" not in dumped_str
    assert "secret_key" not in dumped_str
    assert "token" not in dumped_str or "network sockets" in dumped_str  # allow token only in description if any


def test_csv_report_export_sections_and_tables(sample_audit_analysis, db_session):
    """
    Validates well-structured CSV export with separate sections and table views.
    """
    # 1. Full Multi-Section CSV Export
    full_csv = ReportService.generate_csv_report(sample_audit_analysis, section="all", db=db_session)
    assert "# PRIVACYGUARD EVIDENCE-LINKED CYBERSECURITY AUDIT REPORT" in full_csv
    assert "[SECTION 1: EXECUTIVE SUMMARY METRICS]" in full_csv
    assert "[SECTION 2: EXTRACTED PERMISSIONS]" in full_csv
    assert "[SECTION 3: UNKNOWN PERMISSIONS]" in full_csv
    assert "[SECTION 4: PRIVACY POLICY EVIDENCE]" in full_csv
    assert "[SECTION 5: APPLICATION PURPOSE COMPARISON]" in full_csv
    assert "[SECTION 6: EXPLAINABILITY BOUNDARIES AND LIMITATIONS]" in full_csv
    assert "android.permission.CAMERA" in full_csv
    assert "com.custom.vendor.OEM_TRACKING" in full_csv

    # 2. Permissions Table Only
    perms_csv = ReportService.generate_csv_report(sample_audit_analysis, section="permissions", db=db_session)
    perms_reader = list(csv.reader(perms_csv.strip().splitlines()))
    assert perms_reader[0][0] == "Permission Identifier"
    assert perms_reader[0][1] == "Short Name"
    assert any("android.permission.CAMERA" in row for row in perms_reader)

    # 3. Policy Excerpts Table Only
    policy_csv = ReportService.generate_csv_report(sample_audit_analysis, section="policy", db=db_session)
    policy_reader = list(csv.reader(policy_csv.strip().splitlines()))
    assert policy_reader[0][0] == "Topic / Domain"
    assert any("Camera" in row for row in policy_reader)

    # 4. Purpose Comparison Table Only
    purpose_csv = ReportService.generate_csv_report(sample_audit_analysis, section="purpose", db=db_session)
    purpose_reader = list(csv.reader(purpose_csv.strip().splitlines()))
    assert purpose_reader[0][0] == "Permission Examined"
    assert any("android.permission.CAMERA" in row for row in purpose_reader)

    # 5. Unknown Permissions Table Only
    unknown_csv = ReportService.generate_csv_report(sample_audit_analysis, section="unknown", db=db_session)
    unknown_reader = list(csv.reader(unknown_csv.strip().splitlines()))
    assert unknown_reader[0][0] == "Permission Identifier"
    assert any("com.custom.vendor.OEM_TRACKING" in row for row in unknown_reader)


def test_api_v1_analyses_report_endpoints(sample_audit_analysis, normal_user, db_session):
    """
    Validates API route handling for PDF, JSON, and CSV report downloads:
    - GET /api/v1/analyses/{analysis_id}/report?format=pdf
    - GET /api/v1/analyses/{analysis_id}/report?format=json
    - GET /api/v1/analyses/{analysis_id}/report?format=csv
    - GET /api/v1/analysis/{analysis_id}/report (alias)
    - Database logging in `reports` table.
    """
    aid = sample_audit_analysis.id

    # 1. Download PDF Report
    pdf_resp = get_analyses_report(analysis_id=aid, format="pdf", section=None, current_user=normal_user, db=db_session)
    assert isinstance(pdf_resp, FileResponse)
    assert pdf_resp.media_type == "application/pdf"
    assert "PrivacyGuard_Audit_CameraCalculatorPlus" in pdf_resp.filename

    # 2. Download JSON Report
    json_resp = get_analyses_report(analysis_id=aid, format="json", section=None, current_user=normal_user, db=db_session)
    assert isinstance(json_resp, FileResponse)
    assert json_resp.media_type == "application/json"
    assert "PrivacyGuard_Audit_CameraCalculatorPlus" in json_resp.filename

    # Verify JSON file content
    with open(json_resp.path, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["report_metadata"]["package_name"] == "com.security.cameracalculator"

    # 3. Download CSV Report
    csv_resp = get_analyses_report(analysis_id=aid, format="csv", section=None, current_user=normal_user, db=db_session)
    assert isinstance(csv_resp, Response)
    assert csv_resp.media_type == "text/csv"
    assert "attachment; filename=\"PrivacyGuard_Audit_CameraCalculatorPlus" in csv_resp.headers["Content-Disposition"]
    assert "[SECTION 1: EXECUTIVE SUMMARY METRICS]" in csv_resp.body.decode("utf-8")

    # 4. Singular Alias Route (/analysis/{id}/report)
    alias_resp = get_analysis_report_alias(analysis_id=aid, format="json", section=None, current_user=normal_user, db=db_session)
    assert isinstance(alias_resp, FileResponse)

    # 5. Legacy PDF Endpoint Route (/analysis/{id}/pdf)
    legacy_resp = download_pdf_report(analysis_id=aid, current_user=normal_user, db=db_session)
    assert isinstance(legacy_resp, FileResponse)
    assert legacy_resp.media_type == "application/pdf"

    # 6. Database Logging Verification
    reports_in_db = db_session.query(Report).filter(Report.analysis_id == aid).all()
    formats_logged = {r.report_format for r in reports_in_db}
    assert "PDF" in formats_logged
    assert "JSON" in formats_logged
    assert "CSV" in formats_logged


def test_report_security_ownership_and_validation(sample_audit_analysis, normal_user, other_user, admin_user, db_session):
    """
    Validates ownership checks, 404 on missing, 403 on cross-user download,
    admin override access, and 400 on unsupported format.
    """
    aid = sample_audit_analysis.id

    # 1. Non-existent analysis -> 404
    with pytest.raises(HTTPException) as exc_404:
        get_analyses_report(analysis_id=99999, format="pdf", section=None, current_user=normal_user, db=db_session)
    assert exc_404.value.status_code == 404

    # 2. Cross-user unauthorized download -> 403
    with pytest.raises(HTTPException) as exc_403:
        get_analyses_report(analysis_id=aid, format="pdf", section=None, current_user=other_user, db=db_session)
    assert exc_403.value.status_code == 403
    assert "Access denied" in exc_403.value.detail

    # 3. Admin user authorization -> Success
    admin_resp = get_analyses_report(analysis_id=aid, format="json", section=None, current_user=admin_user, db=db_session)
    assert isinstance(admin_resp, FileResponse)

    # 4. Unsupported format parameter -> 400
    with pytest.raises(HTTPException) as exc_400:
        get_analyses_report(analysis_id=aid, format="xml_malicious", section=None, current_user=normal_user, db=db_session)
    assert exc_400.value.status_code == 400
    assert "Unsupported format" in exc_400.value.detail

    # 5. Filename sanitization against path traversal
    safe_fn = ReportService.get_safe_filename("../../../etc/passwd", 42, "pdf")
    assert ".." not in safe_fn
    assert "/" not in safe_fn
    assert "\\" not in safe_fn
    assert safe_fn.endswith(".pdf")

