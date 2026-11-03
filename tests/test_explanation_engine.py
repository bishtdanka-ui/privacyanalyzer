from backend.services.explanation_engine import ExplanationEngine
from backend.services.manifest_parser import ManifestParser

def test_safe_app_explanation_engine():
    safe_xml = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.safe">
        <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34" />
        <uses-permission android:name="android.permission.VIBRATE" />
        <application android:label="Safe App">
            <activity android:name=".Main" android:exported="true" />
        </application>
    </manifest>
    """
    parsed = ManifestParser.parse_xml_content(safe_xml)
    result = ExplanationEngine.analyze(parsed)

    assert result["risk_level"] == "LOW"
    assert result["risk_score"] < 30.0
    assert result["dangerous_count"] == 0
    assert len(result["combo_findings"]) == 0

def test_spyware_app_combo_detection():
    spyware_xml = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.spyware">
        <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="28" />
        <uses-permission android:name="android.permission.CAMERA" />
        <uses-permission android:name="android.permission.RECORD_AUDIO" />
        <uses-permission android:name="android.permission.INTERNET" />
        <uses-permission android:name="android.permission.READ_SMS" />
        <application android:label="Flashlight Utility">
            <activity android:name=".Main" android:exported="true" />
        </application>
    </manifest>
    """
    parsed = ManifestParser.parse_xml_content(spyware_xml)
    result = ExplanationEngine.analyze(parsed)

    assert result["risk_level"] in ("HIGH", "CRITICAL")
    assert result["risk_score"] >= 50.0
    assert result["dangerous_count"] >= 3

    # Check for Surveillance combo finding
    combo_ids = [c["id"] for c in result["combo_findings"]]
    assert "surveillance_combo" in combo_ids
    assert "banking_sms_interception" in combo_ids
