"""
Unit and Integration Tests for AndroidManifest.xml Extraction Engine
Problem Statement: PS02 - Explainable Cybersecurity Application Privacy & Permission Analyzer

Tests Coverage:
1. Valid XML extraction
2. Malformed XML validation and safe rejection
3. Non-manifest root element handling
4. Namespace handling (standard Android NS, custom NS, unprefixed)
5. uses-permission, uses-permission-sdk-23, and uses-permission-sdk-m extraction
6. maxSdkVersion extraction on permission declarations
7. Structural XPath-like source traceability (/manifest/uses-permission[n])
8. Duplicate declaration identification and counting
9. Unknown permissions & unsupported manifest declarations
10. Malicious XML entity expansion (Billion Laughs / XXE) prevention via defusedxml
11. Size limit enforcement (> 5 MB)
12. Binary compiled AXML rejection
13. Database persistence and authenticated API endpoint (POST /api/v1/analyze/manifest)
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock
from sqlalchemy.orm import Session

from backend.manifest_parser import (
    AndroidManifestParser,
    ManifestParser,
    ManifestParseError,
    ManifestSecurityError,
    XMLSizeLimitExceededError
)
from backend.database import SessionLocal
from backend.models.user import User
from backend.models.analysis import Analysis
from backend.models.permission import Permission
from backend.schemas.analysis import ManifestAnalysisRequest
from backend.routers.analysis import analyze_manifest_post

BASE_DIR = Path(__file__).resolve().parent.parent


def test_parse_safe_calculator_manifest():
    manifest_file = BASE_DIR / "data" / "sample_manifests" / "sample_safe_calculator.xml"
    with open(manifest_file, "r", encoding="utf-8") as f:
        xml_content = f.read()

    result = ManifestParser.parse(xml_content, source_name="sample_safe_calculator.xml")
    assert result["package_name"] == "com.example.simplecalculator"
    assert "android.permission.INTERNET" in result["permissions"]
    assert "android.permission.VIBRATE" in result["permissions"]
    assert "android.permission.CAMERA" not in result["permissions"]
    assert result["exported_count"] >= 1
    assert result["source_file"] == "sample_safe_calculator.xml"


def test_parse_malicious_spyware_manifest():
    manifest_file = BASE_DIR / "data" / "sample_manifests" / "sample_malicious_spyware.xml"
    with open(manifest_file, "r", encoding="utf-8") as f:
        xml_content = f.read()

    result = ManifestParser.parse(xml_content)
    assert result["package_name"] == "com.superboost.flashlight.free"
    assert "android.permission.RECORD_AUDIO" in result["permissions"]
    assert "android.permission.CAMERA" in result["permissions"]
    assert "android.permission.READ_SMS" in result["permissions"]
    assert "android.permission.ACCESS_FINE_LOCATION" in result["permissions"]
    assert result["dangerous_count"] >= 4
    assert result["exported_count"] >= 2


def test_parse_invalid_xml_error():
    malformed_xml = "<manifest package='bad'><unclosed>"
    with pytest.raises(ManifestParseError) as exc_info:
        AndroidManifestParser.parse(malformed_xml)
    assert "Malformed AndroidManifest.xml" in str(exc_info.value)


def test_parse_empty_content_error():
    with pytest.raises(ManifestParseError) as exc_info:
        AndroidManifestParser.parse("")
    assert "empty" in str(exc_info.value).lower()


def test_non_manifest_root_element():
    invalid_root_xml = """<?xml version="1.0" encoding="utf-8"?>
    <configuration xmlns:android="http://schemas.android.com/apk/res/android">
        <uses-permission android:name="android.permission.INTERNET" />
    </configuration>
    """
    with pytest.raises(ManifestParseError) as exc_info:
        AndroidManifestParser.parse(invalid_root_xml)
    assert "Root element must be <manifest>" in str(exc_info.value)


def test_namespace_handling_and_sdk_versions():
    """Verify that Android namespace variants, uses-sdk, and package attributes parse correctly."""
    xml_with_namespaces = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="org.security.audit.sample"
        android:versionCode="42"
        android:versionName="2.5.0">
        <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34" android:maxSdkVersion="35" />
        <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
    </manifest>
    """
    result = AndroidManifestParser.parse(xml_with_namespaces)
    assert result["package_name"] == "org.security.audit.sample"
    assert result["version_code"] == "42"
    assert result["version_name"] == "2.5.0"
    assert result["min_sdk"] == "24"
    assert result["target_sdk"] == "34"
    assert result["max_sdk_version"] == "35"
    assert "android.permission.POST_NOTIFICATIONS" in result["permissions"]


def test_sdk_23_and_sdk_m_declarations_and_max_sdk():
    """Verify extraction of uses-permission-sdk-23, uses-permission-sdk-m, and maxSdkVersion."""
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.sdkdeclarations">
        <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" android:maxSdkVersion="28" />
        <uses-permission-sdk-23 android:name="android.permission.ACCESS_FINE_LOCATION" />
        <uses-permission-sdk-m android:name="android.permission.USE_BIOMETRIC" />
    </manifest>
    """
    result = AndroidManifestParser.parse(xml_content)
    records = result["permission_records"]
    assert len(records) == 3

    # 1. uses-permission with maxSdkVersion
    storage_rec = next(r for r in records if r["permission_name"] == "android.permission.WRITE_EXTERNAL_STORAGE")
    assert storage_rec["declaration_type"] == "uses-permission"
    assert storage_rec["max_sdk_version"] == 28
    assert storage_rec["source_reference"] == "/manifest/uses-permission[1]"

    # 2. uses-permission-sdk-23
    loc_rec = next(r for r in records if r["permission_name"] == "android.permission.ACCESS_FINE_LOCATION")
    assert loc_rec["declaration_type"] == "uses-permission-sdk-23"
    assert loc_rec["max_sdk_version"] is None
    assert loc_rec["source_reference"] == "/manifest/uses-permission-sdk-23[1]"

    # 3. uses-permission-sdk-m
    bio_rec = next(r for r in records if r["permission_name"] == "android.permission.USE_BIOMETRIC")
    assert bio_rec["declaration_type"] == "uses-permission-sdk-m"
    assert bio_rec["source_reference"] == "/manifest/uses-permission-sdk-m[1]"


def test_structural_source_references_and_xpath_traceability():
    """Verify that source references follow sequential structural XPath-like notation without line fabrication."""
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.traceability">
        <uses-permission android:name="android.permission.CAMERA" />
        <uses-permission android:name="android.permission.RECORD_AUDIO" />
        <uses-permission android:name="android.permission.INTERNET" />
    </manifest>
    """
    result = AndroidManifestParser.parse(xml_content, source_name="CustomAppManifest.xml")
    records = result["permission_records"]
    assert records[0]["source_reference"] == "/manifest/uses-permission[1]"
    assert records[0]["source_file"] == "CustomAppManifest.xml"
    assert records[1]["source_reference"] == "/manifest/uses-permission[2]"
    assert records[2]["source_reference"] == "/manifest/uses-permission[3]"


def test_duplicate_permission_identification():
    """Verify duplicate declarations are flagged with is_duplicate and counted correctly."""
    xml_with_duplicates = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.duplicates">
        <uses-permission android:name="android.permission.CAMERA" />
        <uses-permission android:name="android.permission.INTERNET" />
        <uses-permission android:name="android.permission.CAMERA" />
    </manifest>
    """
    result = AndroidManifestParser.parse(xml_with_duplicates)
    assert result["total_permissions"] == 3
    assert result["unique_permissions"] == 2
    assert result["duplicate_count"] == 1

    records = result["permission_records"]
    cam_first = records[0]
    cam_second = records[2]

    assert cam_first["permission_name"] == "android.permission.CAMERA"
    assert cam_first["is_duplicate"] is False

    assert cam_second["permission_name"] == "android.permission.CAMERA"
    assert cam_second["is_duplicate"] is True
    assert cam_second["source_reference"] == "/manifest/uses-permission[3]"


def test_unknown_permissions_and_unsupported_manifest_declarations():
    """Verify unsupported tags and uncataloged permissions are flagged accurately without hallucinations."""
    xml_with_unknowns = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.unknowns">
        <uses-permission android:name="com.oem.vendor.SECRET_DIAGNOSTIC_TELEMETRY" />
        <unsupported-security-hook vendor="proprietary" />
    </manifest>
    """
    result = AndroidManifestParser.parse(xml_with_unknowns)
    
    # Permission verification
    records = result["permission_records"]
    assert len(records) == 1
    rec = records[0]
    assert rec["permission_name"] == "com.oem.vendor.SECRET_DIAGNOSTIC_TELEMETRY"
    assert rec["is_known"] is False
    assert rec["category"] == "Unknown"
    assert rec["protection_level"] == "unknown"
    assert rec["risk_level"] == "UNKNOWN"

    # Unsupported manifest child element verification
    unsupported = result["unsupported_declarations"]
    assert len(unsupported) == 1
    assert unsupported[0]["clean_tag"] == "unsupported-security-hook"
    assert unsupported[0]["source_reference"] == "/manifest/unsupported-security-hook[1]"


def test_malicious_xml_entity_expansion_prevention():
    """Verify that defusedxml blocks DTD entity expansions (Billion Laughs / quadratic blowup)."""
    malicious_entity_xml = """<?xml version="1.0"?>
    <!DOCTYPE lolz [
     <!ENTITY lol "lol">
     <!ELEMENT lolz (#PCDATA)>
     <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
     <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
    ]>
    <manifest package="com.attack.xxe">
        <uses-permission android:name="android.permission.CAMERA" />
    </manifest>
    """
    with pytest.raises(ManifestSecurityError) as exc_info:
        AndroidManifestParser.parse(malicious_entity_xml)
    assert "Security Violation" in str(exc_info.value)
    assert "DTD" in str(exc_info.value) or "entity" in str(exc_info.value).lower()


def test_size_limit_enforcement():
    """Verify that manifests larger than 5 MB are rejected before parsing."""
    huge_payload = "<manifest package='com.huge'>" + (" " * (5 * 1024 * 1024 + 100)) + "</manifest>"
    with pytest.raises(XMLSizeLimitExceededError) as exc_info:
        AndroidManifestParser.parse(huge_payload)
    assert "exceeds maximum limit" in str(exc_info.value)


def test_binary_compiled_axml_rejection():
    """Verify compiled binary AndroidManifest.xml (0x00080003 magic bytes) is cleanly rejected."""
    binary_axml_bytes = b"\x03\x00\x08\x00" + b"\x00" * 64
    with pytest.raises(ManifestParseError) as exc_info:
        AndroidManifestParser.parse(binary_axml_bytes)
    assert "Compiled binary AndroidManifest.xml detected" in str(exc_info.value)


def test_api_v1_analyze_manifest_endpoint_and_db_persistence():
    """Test POST /api/v1/analyze/manifest saves relational analysis for the authenticated user."""
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.email == "manifest_user@example.com").first()
        if not user:
            user = User(
                email="manifest_user@example.com",
                full_name="Manifest Tester",
                password_hash="mock_hash_for_test",
                role="user",
                is_active=True
            )
            db.add(user)
            db.commit()
            db.refresh(user)

        manifest_sample = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.example.secureapp"
            android:versionCode="10"
            android:versionName="1.0.0">
            <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34" />
            <uses-permission android:name="android.permission.CAMERA" />
            <uses-permission android:name="android.permission.INTERNET" />
            <application android:label="Secure Test App" />
        </manifest>
        """

        mock_request = MagicMock()
        mock_request.client.host = "127.0.0.1"

        req = ManifestAnalysisRequest(
            manifest_xml=manifest_sample,
            privacy_policy_text=None,
            source_file="AndroidManifest.xml"
        )

        response = analyze_manifest_post(
            req=req,
            request=mock_request,
            current_user=user,
            db=db
        )

        assert response.id is not None
        assert response.package_name == "com.example.secureapp"
        assert response.app_name == "Secure Test App"
        assert response.total_permissions == 2
        assert response.unique_permissions == 2
        assert response.dangerous_count == 1  # CAMERA
        assert response.normal_count == 1     # INTERNET

        # Verify permission record structure
        cam_p = next(p for p in response.permissions if p.permission_name == "android.permission.CAMERA")
        assert cam_p.declaration_type == "uses-permission"
        assert cam_p.source_reference == "/manifest/uses-permission[1]"
        assert cam_p.category == "Camera"
        assert cam_p.protection_level == "dangerous"
        assert cam_p.risk_level == "HIGH"
        assert "This application declares camera access" in cam_p.explanation
        assert "alone does not prove" in cam_p.explanation
        assert any("Image" in s for s in cam_p.sensitive_data)

        # Verify database relational persistence
        saved_analysis = db.query(Analysis).filter(Analysis.id == response.id).first()
        assert saved_analysis is not None
        assert saved_analysis.user_id == user.id
        assert saved_analysis.package_name == "com.example.secureapp"

        saved_permissions = db.query(Permission).filter(Permission.analysis_id == response.id).all()
        assert len(saved_permissions) == 2
        assert any(p.name == "android.permission.CAMERA" and p.source_reference == "/manifest/uses-permission[1]" for p in saved_permissions)
        assert any(p.name == "android.permission.INTERNET" and p.source_reference == "/manifest/uses-permission[2]" for p in saved_permissions)

    finally:
        db.close()
