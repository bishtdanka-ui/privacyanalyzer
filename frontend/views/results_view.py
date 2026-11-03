import streamlit as st
import pandas as pd
from frontend.api_client import api_client
from frontend.state import set_page

RISK_BADGES = {
    "CRITICAL": "🔴 CRITICAL RISK",
    "HIGH": "🟠 HIGH RISK",
    "MEDIUM": "🟡 MEDIUM RISK",
    "LOW": "🟢 LOW RISK"
}

def render_results_view():
    data = st.session_state.get("active_analysis")
    if not data:
        st.warning("No active analysis selected. Please run an audit or select one from history.")
        if st.button("Go to New Analysis"):
            set_page("New Analysis")
        return

    token = st.session_state.get("token")
    risk_level = data.get("risk_level", "LOW")
    risk_score = data.get("risk_score", 0.0)
    badge = RISK_BADGES.get(risk_level, f"⚪ {risk_level}")

    # Header section
    top_col1, top_col2 = st.columns([3, 1])
    with top_col1:
        st.markdown(f"## 📋 Audit Report: {data.get('app_name')}")
        st.markdown(f"Package: `{data.get('package_name')}` | Version: `{data.get('version_name')}` (`v{data.get('version_code')}`)")
    with top_col2:
        st.markdown(f"### {badge}")
        st.progress(min(max(risk_score / 100.0, 0.0), 1.0))
        st.caption(f"Explainable Risk Score: **{risk_score} / 100**")

    st.divider()

    # Metric summary row
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Permissions", data.get("total_permissions", 0))
    c2.metric("Dangerous Permissions", data.get("dangerous_count", 0), delta_color="inverse")
    c3.metric("Special Permissions", data.get("special_count", 0))
    c4.metric("Exported Components", data.get("exported_components_count", 0))
    c5.metric("Target SDK", data.get("target_sdk", "N/A"))

    # Download PDF Action
    analysis_id = data.get("id")
    if analysis_id:
        st.markdown("---")
        pdf_col1, pdf_col2 = st.columns([2, 1])
        with pdf_col1:
            st.markdown("📄 **Official Security Audit Certificate & ReportLab PDF Available**")
        with pdf_col2:
            success, pdf_bytes = api_client.download_pdf(analysis_id, token)
            if success:
                st.download_button(
                    label="⬇️ Download Audit Report (PDF)",
                    data=pdf_bytes,
                    file_name=f"Security_Audit_{data.get('package_name')}.pdf",
                    mime="application/pdf",
                    type="primary",
                    use_container_width=True
                )
            else:
                st.button("PDF Generation Error", disabled=True)

    # 1. Multi-Permission Threat Chains / Correlated Attacks
    st.markdown("### 1. ⚔️ Multi-Permission Threat Chains")
    combos = data.get("combo_findings", [])
    if combos:
        st.warning(f"⚠️ Detected **{len(combos)} high-risk multi-permission correlation chains** commonly associated with spyware or fraud:")
        for c in combos:
            with st.container(border=True):
                st.markdown(f"#### 🚨 {c.get('name')} (`{c.get('severity')}` - Penalty: +{c.get('risk_penalty')} pts)")
                st.markdown(f"**Triggered by:** `{', '.join(c.get('matched_permissions', []))}`")
                st.markdown(f"**Explainable Scenario:** {c.get('explanation')}")
    else:
        st.success("✓ No multi-permission correlation attack chains (e.g. surveillance, background tracking) were triggered.")

    # 2. Privacy Policy Discrepancy Findings
    st.markdown("### 2. 📑 Privacy Policy & Disclosure Discrepancies")
    discrepancies = data.get("discrepancies", [])
    if discrepancies:
        for d in discrepancies:
            issue = d.get("issue_type")
            sev = d.get("severity")
            if issue == "DECEPTIVE_CONTRADICTION":
                st.error(f"❌ **CRITICAL CONTRADICTION ({d.get('permission_name')}):** {d.get('explanation')}\n\n**Actionable Fix:** {d.get('remediation')}")
            elif issue == "UNDISCLOSED_DANGEROUS_PERMISSION":
                st.warning(f"⚠️ **UNDISCLOSED SENSITIVE PERMISSION ({d.get('permission_name')}):** {d.get('explanation')}\n\n**Actionable Fix:** {d.get('remediation')}")
            else:
                st.info(f"ℹ️ **ADVISORY ({d.get('permission_name')}):** {d.get('explanation')}\n\n**Actionable Fix:** {d.get('remediation')}")
    else:
        st.success("✓ All declared permissions align transparently with policy disclosures.")

    # 3. Interactive Permission Deep Dive Matrix
    st.markdown("### 3. 🛡️ Permission Explainability Deep Dive")
    permissions = data.get("permissions", [])
    
    filter_choice = st.radio(
        "Filter Permissions By Classification:",
        ["All Permissions", "Dangerous Only", "Special Only", "Normal Only"],
        horizontal=True
    )

    filtered_perms = permissions
    if filter_choice == "Dangerous Only":
        filtered_perms = [p for p in permissions if p.get("protection_level") == "dangerous"]
    elif filter_choice == "Special Only":
        filtered_perms = [p for p in permissions if p.get("protection_level") in ("special", "signature/special")]
    elif filter_choice == "Normal Only":
        filtered_perms = [p for p in permissions if p.get("protection_level") == "normal"]

    if filtered_perms:
        for p in filtered_perms:
            prot = p.get("protection_level")
            prot_color = "red" if prot in ("dangerous", "special") else "green"
            with st.expander(f"**{p.get('short_name')}** ({p.get('group')}) — :{prot_color}[{prot.upper()}] — Severity: {p.get('severity_score')}/10"):
                st.markdown(f"**Canonical Identifier:** `{p.get('name')}`")
                st.markdown(f"**Capability Description:** {p.get('description')}")
                st.markdown(f"**Privacy Threat Impact:** {p.get('privacy_risk')}")
                
                scenarios = p.get("abuse_scenarios", [])
                if scenarios:
                    st.markdown("**Real-World Abuse Scenarios:**")
                    for s in scenarios:
                        st.markdown(f"- {s}")
                
                st.markdown(f"**Developer Best-Practice Remediation:** `{p.get('remediation')}`")
                
                disc_status = p.get("discrepancy_status", "NORMAL")
                if disc_status != "NORMAL":
                    st.caption(f"Policy Status Flag: **{disc_status}**")
    else:
        st.info("No permissions found matching the selected filter.")

    # 4. Target SDK & Exported Component Exposure
    st.markdown("### 4. ⚙️ Component Exposure & Platform Security Posture")
    sdk_warnings = data.get("target_sdk_warnings", [])
    if sdk_warnings:
        for w in sdk_warnings:
            st.warning(f"⚠️ {w}")
    else:
        st.success(f"✓ Target SDK `{data.get('target_sdk')}` complies with modern Android runtime sandbox guarantees.")

    st.markdown("---")
    if st.button("⬅️ Run Another Audit", use_container_width=True):
        set_page("New Analysis")

