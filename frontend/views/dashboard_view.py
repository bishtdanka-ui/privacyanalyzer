"""
PrivacyGuard — Security Operations Dashboard
Real-time metrics, risk distribution visualization, and recent audit history.
"""

import streamlit as st
import pandas as pd
from frontend.api_client import api_client
from frontend.state import set_page
from frontend.theme import render_brand_header, get_risk_badge_html

def render_dashboard_view():
    user = st.session_state.get("user", {})
    token = st.session_state.get("token")
    user_name = user.get("full_name") or user.get("email", "Security Analyst")

    render_brand_header(
        title="📊 Security Operations Dashboard",
        subtitle=f"Welcome, {user_name} | Role: {user.get('role', 'user').upper()} | Persistent Tenant ID: #{user.get('id')}"
    )

    # 1. Fetch live metrics from database
    with st.spinner("Loading real-time audit telemetry..."):
        succ_metrics, metrics_data = api_client.get_dashboard_metrics(token)
        succ_hist, history_data = api_client.get_history(token)

    if not succ_metrics or not isinstance(metrics_data, dict):
        metrics_data = {
            "total_analyses": 0,
            "total_permissions": 0,
            "high_risks": 0,
            "unknown_permissions": 0,
            "risk_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "recent_analyses": []
        }

    total_analyses = metrics_data.get("total_analyses", 0)
    total_permissions = metrics_data.get("total_permissions", 0)
    high_risks = metrics_data.get("high_risks", 0)
    unknown_perms = metrics_data.get("unknown_permissions", 0)
    risk_dist = metrics_data.get("risk_distribution", {})

    # Top Metric KPI Row
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Analyses", total_analyses, help="Total applications analyzed and persisted in database.")
    m2.metric("Permissions Analyzed", total_permissions, help="Total Android permissions audited across all manifests.")
    m3.metric("High-Risk Findings", high_risks, delta_color="inverse", help="Total applications flagged with HIGH or CRITICAL risk scores.")
    m4.metric("Unknown Permissions", unknown_perms, help="Proprietary or uncataloged permissions detected.")

    st.markdown("---")

    col_main, col_side = st.columns([3, 2])

    with col_main:
        st.subheader("📈 Risk Distribution & Security Posture")
        if total_analyses > 0:
            chart_df = pd.DataFrame([
                {"Risk Level": "Critical", "Applications": risk_dist.get("CRITICAL", 0)},
                {"Risk Level": "High", "Applications": risk_dist.get("HIGH", 0)},
                {"Risk Level": "Medium", "Applications": risk_dist.get("MEDIUM", 0)},
                {"Risk Level": "Low", "Applications": risk_dist.get("LOW", 0)}
            ]).set_index("Risk Level")
            st.bar_chart(chart_df, color="#38BDF8")
        else:
            st.info("No applications analyzed yet. The risk distribution chart will populate once your first audit is run.")

        st.subheader("📑 Recent Analysis History")
        recent = metrics_data.get("recent_analyses", [])
        if recent:
            df_recent = pd.DataFrame(recent)
            df_display = df_recent[["id", "app_name", "package_name", "risk_level", "risk_score", "total_permissions", "created_at"]].copy()
            df_display.rename(columns={
                "id": "Audit ID",
                "app_name": "Application",
                "package_name": "Package ID",
                "risk_level": "Risk Level",
                "risk_score": "Score (/100)",
                "total_permissions": "Permissions",
                "created_at": "Timestamp"
            }, inplace=True)
            st.dataframe(df_display, use_container_width=True, hide_index=True)

            # Quick Inspect Dropdown
            audit_ids = [r["id"] for r in recent]
            selected_id = st.selectbox("Quick Inspect Full Report for Audit ID:", audit_ids, key="dash_select_id")
            if st.button("🔍 Open Full Explainable Report", use_container_width=True):
                with st.spinner("Retrieving analysis details from database..."):
                    s, details = api_client.get_analysis_details(selected_id, token)
                    if s:
                        st.session_state["active_analysis"] = details
                        set_page("Results")
                    else:
                        st.error(str(details))
        else:
            st.info("No audit history found. Run your first analysis below to generate evidence-grounded reports.")

    with col_side:
        st.subheader("⚡ Quick Analysis Actions")
        with st.container(border=True):
            st.markdown("#### 🚀 Launch New Analysis Wizard")
            st.markdown("Upload an `AndroidManifest.xml` or enter permissions manually to cross-examine against user purpose and privacy policies.")
            if st.button("Start New Analysis →", type="primary", use_container_width=True):
                set_page("New Analysis")

        with st.container(border=True):
            st.markdown("#### 🧪 Security Benchmark Scenarios")
            st.markdown("Explore pre-loaded test applications including flashlight spyware, mobile fintech banking, and minimal utilities.")
            if st.button("Explore Benchmarks →", use_container_width=True):
                set_page("New Analysis")

        with st.container(border=True):
            st.markdown("#### 🛡️ Explainable Security Features")
            st.markdown("""
            - **Defusedxml Engine:** Blocks XML entity expansion & malicious DTD injections.
            - **Curated Knowledge Base:** 36 verified Android permissions with platform context.
            - **Purpose Matching:** Detects purpose mismatches without falsely labeling apps as malware.
            - **ReportLab PDF Certificates:** Official tamper-evident PDF export.
            """)
