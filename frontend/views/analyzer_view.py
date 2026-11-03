import streamlit as st
from pathlib import Path
from frontend.api_client import api_client
from frontend.state import set_page

BASE_DIR = Path(__file__).resolve().parent.parent.parent

BENCHMARKS = {
    "Super Bright LED Flashlight (High-Risk Spyware/Stalkerware)": {
        "manifest_path": BASE_DIR / "data" / "sample_manifests" / "sample_malicious_spyware.xml",
        "policy_path": BASE_DIR / "data" / "sample_manifests" / "sample_policy_deceptive.txt",
        "description": "Flashlight utility that requests Camera, Audio, Fine/Background Location, SMS, and Contacts while explicitly claiming in its policy that it does NOT collect SMS or location."
    },
    "Apex Vault Mobile Banking (Legitimate Fintech with Checks)": {
        "manifest_path": BASE_DIR / "data" / "sample_manifests" / "sample_fintech_banking.xml",
        "policy_path": BASE_DIR / "data" / "sample_manifests" / "sample_policy_transparent.txt",
        "description": "Mobile banking app with Camera for check deposit and Coarse Location for ATMs, transparently matching its privacy disclosures."
    },
    "Smart Calculator (Minimal Benign Utility)": {
        "manifest_path": BASE_DIR / "data" / "sample_manifests" / "sample_safe_calculator.xml",
        "policy_path": None,
        "description": "Clean utility requesting only VIBRATE and INTERNET for ads, zero sensitive runtime permissions."
    }
}

def render_analyzer_view():
    st.markdown("## 🔍 Explainable Application Privacy & Permission Analyzer")
    st.markdown("Upload or paste an `AndroidManifest.xml` file and cross-examine it against developer privacy policy disclosures.")
    st.divider()

    token = st.session_state.get("token")

    tab_benchmark, tab_upload, tab_paste = st.tabs([
        "🧪 Pre-Loaded Security Benchmarks",
        "📁 Upload XML & Policy Files",
        "✏️ Direct XML & Text Editor"
    ])

    manifest_xml_to_run = ""
    policy_text_to_run = ""

    with tab_benchmark:
        st.subheader("Load Hackathon Pre-Configured Benchmark Scenarios")
        st.markdown("Select a real-world benchmark scenario to immediately test the explainability engine:")
        
        selected_bench = st.selectbox("Benchmark Target Scenario:", list(BENCHMARKS.keys()))
        bench_info = BENCHMARKS[selected_bench]
        st.info(f"**Scenario Profile:** {bench_info['description']}")

        # Read files
        if bench_info["manifest_path"].exists():
            with open(bench_info["manifest_path"], "r", encoding="utf-8") as f:
                bench_xml = f.read()
        else:
            bench_xml = ""

        bench_policy = ""
        if bench_info.get("policy_path") and bench_info["policy_path"].exists():
            with open(bench_info["policy_path"], "r", encoding="utf-8") as f:
                bench_policy = f.read()

        with st.expander("👁️ Preview Benchmark AndroidManifest.xml"):
            st.code(bench_xml, language="xml")

        if bench_policy:
            with st.expander("👁️ Preview Benchmark Privacy Policy"):
                st.text(bench_policy)

        if st.button(f"⚡ Audit '{selected_bench.split('(')[0].strip()}' Benchmark", type="primary", key="btn_run_bench"):
            manifest_xml_to_run = bench_xml
            policy_text_to_run = bench_policy

    with tab_upload:
        st.subheader("Upload Custom Application Manifest & Policy")
        col_up1, col_up2 = st.columns(2)
        with col_up1:
            uploaded_manifest = st.file_uploader(
                "Upload AndroidManifest.xml",
                type=["xml"],
                help="Select a readable AndroidManifest.xml file."
            )
        with col_up2:
            uploaded_policy = st.file_uploader(
                "Upload Privacy Policy (Optional .txt)",
                type=["txt", "md"],
                help="Optional privacy policy text file to cross-check permission claims."
            )

        policy_paste_opt = st.text_area(
            "Or Paste Privacy Policy Text Directly Here:",
            height=120,
            placeholder="e.g. We respect your privacy. We do not collect location or SMS data..."
        )

        if st.button("🚀 Run Explainable Audit on Uploaded Files", type="primary", key="btn_run_upload"):
            if not uploaded_manifest:
                st.error("Please upload an AndroidManifest.xml file first.")
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
                elif policy_paste_opt:
                    policy_text_to_run = policy_paste_opt

    with tab_paste:
        st.subheader("Direct Manifest & Policy Text Editor")
        paste_xml = st.text_area(
            "Paste AndroidManifest.xml String:",
            height=250,
            placeholder="<manifest package='com.example.app'>\n  <uses-permission android:name='android.permission.CAMERA'/>\n...</manifest>"
        )
        paste_pol = st.text_area(
            "Paste Privacy Policy Text (Optional):",
            height=150,
            placeholder="We do not track location or microphone audio..."
        )

        if st.button("🚀 Run Explainable Audit on Pasted Text", type="primary", key="btn_run_paste"):
            if not paste_xml or not paste_xml.strip():
                st.error("Please paste a valid AndroidManifest.xml string.")
            else:
                manifest_xml_to_run = paste_xml
                policy_text_to_run = paste_pol

    # Execution handler
    if manifest_xml_to_run:
        with st.spinner("Executing DefusedXML Parser & Multi-Permission Explainability Engine..."):
            success, result = api_client.analyze_manifest_text(
                manifest_xml=manifest_xml_to_run,
                policy_text=policy_text_to_run,
                token=token
            )
            if success:
                st.session_state["active_analysis"] = result
                st.success(f"Audit completed successfully for {result.get('package_name')}! Redirecting to report...")
                set_page("Results")
            else:
                st.error(f"Analysis failed: {result}")

