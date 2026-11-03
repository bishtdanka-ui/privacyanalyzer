import streamlit as st
import pandas as pd
from frontend.api_client import api_client
from frontend.state import set_page

def render_dashboard_view():
    user = st.session_state.get("user", {})
    token = st.session_state.get("token")

    st.markdown(f"## 📊 Security Operations Dashboard")
    st.markdown(f"Logged in as **{user.get('full_name') or user.get('username')}** (`{user.get('role').upper()}` role) | ID: `{user.get('id')}`")
    st.divider()

    # Load history for user stats
    success, history_data = api_client.get_history(token)
    if not success or not isinstance(history_data, list):
        history_data = []

    total_audits = len(history_data)
    critical_count = sum(1 for h in history_data if h.get("risk_level") == "CRITICAL")
    high_count = sum(1 for h in history_data if h.get("risk_level") == "HIGH")
    medium_count = sum(1 for h in history_data if h.get("risk_level") == "MEDIUM")
    low_count = sum(1 for h in history_data if h.get("risk_level") == "LOW")

    # Metrics row
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total Audits Run", total_audits)
    m2.metric("Critical Risks", critical_count, delta_color="inverse")
    m3.metric("High Risks", high_count, delta_color="inverse")
    m4.metric("Medium Risks", medium_count)
    m5.metric("Verified Low Risk", low_count)

    st.markdown("---")

    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.subheader("📑 Recent Application Audits")
        if history_data:
            df = pd.DataFrame(history_data)
            df_display = df[["id", "app_name", "package_name", "risk_level", "risk_score", "dangerous_count", "created_at"]].copy()
            df_display.rename(columns={
                "id": "Audit ID",
                "app_name": "Application",
                "package_name": "Package ID",
                "risk_level": "Risk Level",
                "risk_score": "Score (/100)",
                "dangerous_count": "Dangerous Perms",
                "created_at": "Timestamp"
            }, inplace=True)
            st.dataframe(df_display, use_container_width=True, hide_index=True)
            
            # Quick Inspect selector
            audit_ids = [h["id"] for h in history_data]
            selected_id = st.selectbox("Inspect Full Report for Audit ID:", audit_ids, key="dash_select_id")
            if st.button("Open Full Explainable Report", use_container_width=True):
                with st.spinner("Retrieving analysis details..."):
                    s, details = api_client.get_analysis_details(selected_id, token)
                    if s:
                        st.session_state["active_analysis"] = details
                        set_page("Results")
                    else:
                        st.error(str(details))
        else:
            st.info("No applications analyzed yet. Launch your first audit below to scan an Android manifest and privacy policy.")

    with col_right:
        st.subheader("⚡ Quick Security Actions")
        st.markdown("""
        Analyze APK permissions, inspect `AndroidManifest.xml` files, and cross-verify with privacy policy disclosures.
        """)
        
        if st.button("🚀 Launch New Application Audit", type="primary", use_container_width=True):
            set_page("Privacy Analyzer")

        if st.button("📂 Load Pre-Built Security Benchmarks", use_container_width=True):
            set_page("Privacy Analyzer")

        st.markdown("#### 🔍 Problem Statement Coverage")
        st.markdown("""
        - **Defusedxml Manifest Parsing:** Rejects XML billion laughs and external entity attacks.
        - **Multi-Permission Correlation:** Flags spyware, stalkerware, and 2FA SMS interception.
        - **Discrepancy Detection:** Identifies contradictions between policy promises and manifest requests.
        - **Exportable PDF Reports:** ReportLab-generated audit certificates.
        """)
