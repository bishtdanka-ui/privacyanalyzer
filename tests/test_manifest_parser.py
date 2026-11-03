import pytest
from pathlib import Path
from backend.services.manifest_parser import ManifestParser, ManifestParseError

BASE_DIR = Path(__file__).resolve().parent.parent

def test_parse_safe_calculator_manifest():
    manifest_file = BASE_DIR / "data" / "sample_manifests" / "sample_safe_calculator.xml"
    with open(manifest_file, "r", encoding="utf-8") as f:
        xml_content = f.read()

    result = ManifestParser.parse_xml_content(xml_content)
    assert result["package_name"] == "com.example.simplecalculator"
    assert "android.permission.INTERNET" in result["permissions"]
    assert "android.permission.VIBRATE" in result["permissions"]
    assert "android.permission.CAMERA" not in result["permissions"]
    assert result["exported_count"] >= 1  # MainActivity is exported launcher

def test_parse_malicious_spyware_manifest():
    manifest_file = BASE_DIR / "data" / "sample_manifests" / "sample_malicious_spyware.xml"
    with open(manifest_file, "r", encoding="utf-8") as f:
        xml_content = f.read()

    result = ManifestParser.parse_xml_content(xml_content)
    assert result["package_name"] == "com.superboost.flashlight.free"
    assert "android.permission.RECORD_AUDIO" in result["permissions"]
    assert "android.permission.CAMERA" in result["permissions"]
    assert "android.permission.READ_SMS" in result["permissions"]
    assert "android.permission.ACCESS_FINE_LOCATION" in result["permissions"]
    assert result["exported_count"] >= 2  # BootReceiver and TelemetryService

def test_parse_invalid_xml_error():
    malformed_xml = "<manifest package='bad'><unclosed>"
    with pytest.raises(ManifestParseError):
        ManifestParser.parse_xml_content(malformed_xml)

def test_parse_empty_content_error():
    with pytest.raises(ManifestParseError):
        ManifestParser.parse_xml_content("")

