"""
PrivacyGuard — New Analysis Wizard
Supports AndroidManifest.xml file upload, manual permission entry, pre-configured benchmarks,
and user-supplied application purpose cross-examination.
"""

import streamlit as st
import re
from pathlib import Path
from frontend.api_client import api_client
from frontend.state import set_page
from frontend.theme import render_brand_header

BASE_DIR = Path(__file__).resolve().parent.parent.parent

COMMON_ANDROID_PERMISSIONS = [
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.SEND_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.NFC",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "android.permission.RECEIVE_BOOT_COMPLETED"
]

BENCHMARKS = {
    "QuickScan Document Manager (Synthetic Sample with Unknown Permission)": {
        "manifest_path": BASE_DIR / "data" / "synthetic_demo" / "sample_manifest.xml",
        "policy_path": BASE_DIR / "data" / "synthetic_demo" / "sample_privacy_policy.txt",
        "app_name": "QuickScan Document Manager",
        "purpose": "Scan receipts and documents using camera, save to storage, and sync to cloud.",
        "description": "Synthetic photo document scanner requesting Camera, Storage, and uncataloged vendor telemetry to showcase unknown permission explainability."
    },
    "Synthetic Minimal Calculator (Clean Arithmetic Utility)": {
        "manifest_path": BASE_DIR / "data" / "synthetic_demo" / "calculator" / "synthetic_calculator_manifest.xml",
        "policy_path": BASE_DIR / "data" / "synthetic_demo" / "calculator" / "synthetic_calculator_policy.txt",
        "app_name": "Synthetic Calculator",
        "purpose": "Simple arithmetic, scientific calculations, and unit conversion.",
        "description": "Synthetic minimal utility requesting only VIBRATE and INTERNET for ads, zero sensitive runtime permissions."
    },
    "RoadMaster Navigation (Synthetic Turn-by-Turn GPS Guidance)": {
        "manifest_path": BASE_DIR / "data" / "synthetic_demo" / "navigation" / "synthetic_navigation_manifest.xml",
        "policy_path": BASE_DIR / "data" / "synthetic_demo" / "navigation" / "synthetic_navigation_policy.txt",
        "app_name": "RoadMaster Navigation",
        "purpose": "Turn-by-turn driving navigation, offline maps, and live traffic alerts.",
        "description": "Synthetic navigation application requesting Fine/Coarse Location, Background Location, and Foreground Service with aligned policy disclosures."
    },
    "Pulse Chat (Synthetic Messaging with Media & Contacts)": {
        "manifest_path": BASE_DIR / "data" / "synthetic_demo" / "messaging" / "synthetic_messaging_manifest.xml",
        "policy_path": BASE_DIR / "data" / "synthetic_demo" / "messaging" / "synthetic_messaging_policy.txt",
        "app_name": "Pulse Chat",
        "purpose": "Real-time encrypted text messaging, photo sharing, voice notes, and contact discovery.",
        "description": "Synthetic multi-capability messaging suite requesting Camera, Audio recording, and Contacts with end-to-end encryption privacy policy."
    },
    "Super Bright LED Flashlight (High-Risk Spyware/Stalkerware Benchmark)": {
        "manifest_path": BASE_DIR / "data" / "sample_manifests" / "sample_malicious_spyware.xml",
        "policy_path": BASE_DIR / "data" / "sample_manifests" / "sample_policy_deceptive.txt",
        "app_name": "Super Bright LED Flashlight",
        "purpose": "A utility flashlight application that activates the device LED flash.",
        "description": "Deceptive flashlight utility requesting Camera, Audio, Location, SMS, and Contacts while falsely claiming in policy that it does NOT collect SMS or location."
    }
}

def generate_synthetic_manifest(app_name: str, package_name: str, permissions: list) -> str:
    """Creates a well-formed readable AndroidManifest.xml from manually entered permissions."""
    safe_pkg = re.sub(r"[^a-zA-Z0-9._]", "", package_name.lower()) or "com.privacyguard.manualapp"
    safe_name = app_name.strip() or "Manual Android Application"
    
    perm_tags = "\n    ".join(
        f'<uses-permission android:name="{p.strip()}" />'
        for p in permissions if p.strip()
    )
    
    return f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{safe_pkg}"
    android:versionCode="1"
    android:versionName="1.0.0">
    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34" />
    {perm_tags}
    <application
        android:label="{safe_name}"
        android:allowBackup="true"
        android:debuggable="false">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>"""

def render_analyzer_view():
    render_brand_header(
        title="🚀 New Application Privacy Analysis Wizard",
        subtitle="Upload an AndroidManifest.xml or enter permissions manually to cross-examine against user purpose and privacy policy disclosures."
    )

    token = st.session_state.get("token")

    tab_upload, tab_manual, tab_benchmark, tab_raw = st.tabs([
        "📁 Upload AndroidManifest.xml",
        "✍️ Manual Permission Entry",
        "🧪 Pre-Loaded Benchmarks",
        "✏️ Direct XML & Policy Editor"
    ])

    manifest_xml_to_run = ""
    policy_text_to_run = ""
    app_purpose_to_run = ""
    app_name_to_run = ""

    # TAB 1: Upload AndroidManifest.xml
    with tab_upload:
        st.subheader("Upload Application Manifest & Optional Privacy Policy")
        col_up_meta1, col_up_meta2 = st.columns(2)
        with col_up_meta1:
            up_app_name = st.text_input("Application Name (Optional)", placeholder="e.g. Acme Messenger", key="up_name")
        with col_up_meta2:
            up_app_purpose = st.text_input(
                "Application Purpose / Intended Use",
                placeholder="e.g. Turn-by-turn navigation, Instant messaging, Simple calculator",
                key="up_purpose",
                help="Supplying application purpose allows the engine to flag purpose mismatches and expected capabilities."
            )

        col_up_f1, col_up_f2 = st.columns(2)
        with col_up_f1:
            uploaded_manifest = st.file_uploader(
                "Upload AndroidManifest.xml",
                type=["xml"],
                help="Select a readable AndroidManifest.xml file.",
                key="up_manifest_file"
            )
        with col_up_f2:
            uploaded_policy = st.file_uploader(
                "Upload Privacy Policy (Optional .txt, .md)",
                type=["txt", "md"],
                help="Optional privacy policy text file to cross-check permission claims.",
                key="up_policy_file"
            )

        up_policy_text = st.text_area(
            "Or Paste Privacy Policy Text Here:",
            height=100,
            placeholder="e.g. We do not collect your location or read your SMS messages...",
            key="up_policy_paste"
        )

        if st.button("🚀 Run Analysis on Uploaded Files", type="primary", key="btn_run_upload", use_container_width=True):
            if not uploaded_manifest:
                st.error("Please select an AndroidManifest.xml file to upload.")
            else:
                try:
                    manifest_xml_to_run = uploaded_manifest.getvalue().decode("utf-8")
                except UnicodeDecodeError:
                    manifest_xml_to_run = uploaded_manifest.getvalue().decode("latin-1", errors="ignore")

                if uploaded_policy:
                    try:
                        policy_text_to_run = uploaded_policy.getvalue().decode("utf-8")
                    except UnicodeDecodeError:
                        policy_text_to_run = uploaded_policy.getvalue().decode("latin-1", errors="ignore")
                elif up_policy_text:
                    policy_text_to_run = up_policy_text

                app_name_to_run = up_app_name
                app_purpose_to_run = up_app_purpose

    # TAB 2: Manual Permission Entry
    with tab_manual:
        st.subheader("Manual Permission Input & Purpose Verification")
        st.caption("Inspect privacy implications for custom permission configurations without requiring an existing XML file.")
        
        col_man1, col_man2 = st.columns(2)
        with col_man1:
            man_app_name = st.text_input("Application Name", value="My Custom App", key="man_name")
            man_pkg_name = st.text_input("Package Identifier", value="com.custom.privacyguard.app", key="man_pkg")
        with col_man2:
            man_purpose = st.text_input(
                "Declared Application Purpose",
                value="Simple arithmetic calculator for daily math.",
                key="man_purpose",
                help="The stated purpose is used to evaluate whether declared permissions are expected or potential anomalies."
            )

        st.markdown("#### Select Permissions to Audit:")
        selected_perms = st.multiselect(
            "Select from Curated Android Permissions Knowledge Base:",
            options=COMMON_ANDROID_PERMISSIONS,
            default=["android.permission.CAMERA", "android.permission.INTERNET"],
            key="man_multiselect"
        )

        custom_perms_input = st.text_area(
            "Or Enter Additional / Custom Permissions (one per line):",
            height=80,
            placeholder="android.permission.RECORD_AUDIO\ncom.custom.vendor.TELEMETRY",
            key="man_custom_perms"
        )

        man_policy = st.text_area(
            "Optional Privacy Policy Text:",
            height=100,
            placeholder="We never access camera or microphone audio...",
            key="man_policy"
        )

        if st.button("🚀 Analyze Manually Entered Permissions", type="primary", key="btn_run_manual", use_container_width=True):
            combined_perms = list(selected_perms)
            if custom_perms_input:
                for line in custom_perms_input.splitlines():
                    clean_l = line.strip()
                    if clean_l and clean_l not in combined_perms:
                        combined_perms.append(clean_l)

            if not combined_perms:
                st.error("Please select or enter at least one permission to analyze.")
            else:
                manifest_xml_to_run = generate_synthetic_manifest(man_app_name, man_pkg_name, combined_perms)
                policy_text_to_run = man_policy
                app_name_to_run = man_app_name
                app_purpose_to_run = man_purpose

    # TAB 3: Pre-Loaded Benchmarks
    with tab_benchmark:
        st.subheader("Load Verified Evaluation Benchmark Scenarios")
        selected_bench = st.selectbox("Benchmark Target Scenario:", list(BENCHMARKS.keys()), key="bench_select")
        bench_info = BENCHMARKS[selected_bench]
        st.info(f"**Scenario Profile:** {bench_info['description']}")
        st.markdown(f"**Configured Purpose:** `{bench_info['purpose']}`")

        bench_xml = ""
        if bench_info["manifest_path"].exists():
            with open(bench_info["manifest_path"], "r", encoding="utf-8") as f:
                bench_xml = f.read()

        bench_policy = ""
        if bench_info.get("policy_path") and bench_info["policy_path"].exists():
            with open(bench_info["policy_path"], "r", encoding="utf-8") as f:
                bench_policy = f.read()

        with st.expander("👁️ Preview Benchmark AndroidManifest.xml"):
            st.code(bench_xml, language="xml")

        if bench_policy:
            with st.expander("👁️ Preview Benchmark Privacy Policy"):
                st.text(bench_policy)

        if st.button(f"⚡ Audit '{bench_info['app_name']}' Benchmark", type="primary", key="btn_run_bench", use_container_width=True):
            manifest_xml_to_run = bench_xml
            policy_text_to_run = bench_policy
            app_name_to_run = bench_info["app_name"]
            app_purpose_to_run = bench_info["purpose"]

    # TAB 4: Raw XML & Text Editor
    with tab_raw:
        st.subheader("Direct XML & Privacy Policy Text Editor")
        raw_purpose = st.text_input("Application Purpose (Optional):", placeholder="e.g. Cloud photo backup", key="raw_purpose")
        raw_xml = st.text_area(
            "Paste Raw AndroidManifest.xml String:",
            height=200,
            placeholder="<manifest package='com.example.app'>\n  <uses-permission android:name='android.permission.CAMERA'/>\n...</manifest>",
            key="raw_xml"
        )
        raw_pol = st.text_area(
            "Paste Privacy Policy Text (Optional):",
            height=120,
            placeholder="We do not track location coordinates or microphone audio...",
            key="raw_pol"
        )

        if st.button("🚀 Run Audit on Pasted Text", type="primary", key="btn_run_raw", use_container_width=True):
            if not raw_xml or not raw_xml.strip():
                st.error("Please paste a valid AndroidManifest.xml string.")
            else:
                manifest_xml_to_run = raw_xml
                policy_text_to_run = raw_pol
                app_purpose_to_run = raw_purpose

    # Centralized Execution Handler
    if manifest_xml_to_run:
        with st.spinner("Executing DefusedXML Parser & Explainability Engine..."):
            success, result = api_client.analyze_manifest_text(
                manifest_xml=manifest_xml_to_run,
                policy_text=policy_text_to_run,
                token=token
            )
            if success:
                analysis_id = result.get("id")
                # If application purpose was provided, also run purpose comparison
                if app_purpose_to_run and analysis_id:
                    api_client.compare_purpose(
                        token=token,
                        app_name=app_name_to_run or result.get("app_name"),
                        app_purpose=app_purpose_to_run,
                        manifest_xml=manifest_xml_to_run,
                        privacy_policy_text=policy_text_to_run,
                        analysis_id=analysis_id
                    )

                st.session_state["active_analysis"] = result
                st.session_state["active_purpose"] = app_purpose_to_run
                st.success(f"Audit completed successfully for {result.get('package_name')}! Redirecting to report...")
                set_page("Results")
            else:
                st.error(f"Analysis failed: {result}")
