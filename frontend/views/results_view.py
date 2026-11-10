"""
PrivacyGuard — Audit Results View
Comprehensive, explainable security audit report featuring risk scores,
multi-permission attack chains, policy discrepancies, purpose alignment questions,
and tamper-evident PDF export.
"""

import streamlit as st
import pandas as pd
from frontend.api_client import api_client
from frontend.state import set_page
from frontend.theme import render_brand_header, get_risk_badge_html

def render_results_view():
    data = st.session_state.get("active_analysis")
    if not data:
        st.warning("No active analysis selected. Please run an audit or select one from history.")
        if st.button("← Go to New Analysis"):
            set_page("New Analysis")
        return

    token = st.session_state.get("token")
    analysis_id = data.get("id")
    app_name = data.get("app_name", "Application")
    pkg_name = data.get("package_name", "unknown.package")
    risk_level = data.get("risk_level", "LOW")
    risk_score = data.get("risk_score", 0.0)
    badge_html = get_risk_badge_html(risk_level)

    # 1. Header Banner
    col_hdr1, col_hdr2 = st.columns([3, 1])
    with col_hdr1:
        render_brand_header(
            title=f"📋 Audit Report: {app_name}",
            subtitle=f"Package: `{pkg_name}` | Version: `{data.get('version_name')}` (Build {data.get('version_code')}) | Target SDK: {data.get('target_sdk')}"
        )
    with col_hdr2:
        st.markdown(f"### {badge_html}", unsafe_allow_html=True)
        st.progress(min(max(risk_score / 100.0, 0.0), 1.0))
        st.caption(f"Explainable Risk Score: **{risk_score} / 100**")

    # 2. Metric KPI Cards Row
    permissions = data.get("permissions", [])
    total_perms = len(permissions)
    dangerous_count = sum(1 for p in permissions if p.get("protection_level") == "dangerous")
    special_count = sum(1 for p in permissions if p.get("protection_level") in ("special", "signature/special"))
    normal_count = sum(1 for p in permissions if p.get("protection_level") == "normal")
    unknown_count = sum(1 for p in permissions if p.get("protection_level") == "unknown")
    known_count = total_perms - unknown_count

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Total Declared", total_perms)
    c2.metric("Known Perms", known_count)
    c3.metric("Dangerous Perms", dangerous_count, delta_color="inverse")
    c4.metric("Special Perms", special_count)
    c5.metric("Normal Perms", normal_count)
    c6.metric("Unknown Perms", unknown_count)

    # Evidence-Linked Analysis Reports Export Bar (PDF, JSON, CSV)
    if analysis_id:
        st.markdown("---")
        st.markdown("### 📥 Download Evidence-Linked Analysis Reports")
        st.caption("Export authoritative audit artifacts with verified source references, policy excerpts, purpose comparisons, and methodology disclosures.")

        rep_c1, rep_c2, rep_c3 = st.columns(3)

        with rep_c1:
            ok_pdf, pdf_bytes = api_client.download_report(analysis_id, token, format="pdf")
            if ok_pdf and isinstance(pdf_bytes, (bytes, bytearray)):
                st.download_button(
                    label="📄 Download PDF Report",
                    data=pdf_bytes,
                    file_name=f"PrivacyGuard_Audit_{pkg_name}_{analysis_id}.pdf",
                    mime="application/pdf",
                    type="primary",
                    use_container_width=True,
                    help="Publication-grade ReportLab PDF complete with cover page, executive summary, 6 core sections, and page numbering."
                )
            else:
                st.button("PDF Unavailable", disabled=True, use_container_width=True)

        with rep_c2:
            ok_json, json_data = api_client.download_report(analysis_id, token, format="json")
            if ok_json:
                import json as py_json
                json_str = py_json.dumps(json_data, indent=2) if isinstance(json_data, dict) else str(json_data)
                st.download_button(
                    label="🧾 Export Findings (JSON)",
                    data=json_str,
                    file_name=f"PrivacyGuard_Audit_{pkg_name}_{analysis_id}.json",
                    mime="application/json",
                    use_container_width=True,
                    help="Complete structured findings with exact XPath source references and analysis metadata."
                )
            else:
                st.button("JSON Unavailable", disabled=True, use_container_width=True)

        with rep_c3:
            ok_csv, csv_text = api_client.download_report(analysis_id, token, format="csv")
            if ok_csv:
                st.download_button(
                    label="📊 Export Tables (CSV)",
                    data=csv_text if isinstance(csv_text, str) else csv_text.decode("utf-8", errors="ignore"),
                    file_name=f"PrivacyGuard_Audit_{pkg_name}_{analysis_id}.csv",
                    mime="text/csv",
                    use_container_width=True,
                    help="Well-structured CSV tables for permissions, policy findings, purpose comparisons, and limitations."
                )
            else:
                st.button("CSV Unavailable", disabled=True, use_container_width=True)

    st.markdown("---")

    # SECTION 1: Multi-Permission Correlation Attack Chains
    st.markdown("### 1. ⚔️ Multi-Permission Threat Chains")
    combos = data.get("combo_findings", [])
    if combos:
        st.warning(f"⚠️ Detected **{len(combos)} high-risk multi-permission correlation chains** commonly associated with surveillance, stalkerware, or OTP fraud:")
        for c in combos:
            with st.container(border=True):
                st.markdown(f"#### 🚨 {c.get('name')} (`{c.get('severity')}` - Risk Penalty: +{c.get('risk_penalty')} pts)")
                st.markdown(f"**Triggered by:** `{', '.join(c.get('matched_permissions', []))}`")
                st.markdown(f"**Explainable Scenario:** {c.get('explanation')}")
    else:
        st.success("✓ No multi-permission correlation attack chains (e.g. ambient surveillance, background tracking) were triggered.")

    # SECTION 2: Privacy Policy & Disclosure Discrepancies
    st.markdown("### 2. 📑 Privacy Policy & Disclosure Discrepancies")
    discrepancies = data.get("discrepancies", [])
    if discrepancies:
        for d in discrepancies:
            issue = d.get("issue_type")
            if issue == "DECEPTIVE_CONTRADICTION":
                st.error(f"❌ **CRITICAL CONTRADICTION ({d.get('permission_name')}):** {d.get('explanation')}\n\n**Actionable Fix:** {d.get('remediation')}")
            elif issue == "UNDISCLOSED_DANGEROUS_PERMISSION":
                st.warning(f"⚠️ **UNDISCLOSED SENSITIVE PERMISSION ({d.get('permission_name')}):** {d.get('explanation')}\n\n**Actionable Fix:** {d.get('remediation')}")
            else:
                st.info(f"ℹ️ **ADVISORY ({d.get('permission_name')}):** {d.get('explanation')}\n\n**Actionable Fix:** {d.get('remediation')}")
    else:
        st.success("✓ All declared permissions align transparently with policy disclosures.")

    # SECTION 3: Purpose & Functionality Alignment (Explainable Questions)
    if analysis_id:
        st.markdown("### 3. 🎯 Purpose & Functionality Alignment")
        findings_succ, findings_resp = api_client.get_analysis_findings(analysis_id, token)
        if findings_succ and findings_resp and "findings" in findings_resp:
            findings_list = findings_resp["findings"]
            if findings_list:
                for f in findings_list:
                    cat = f.get("finding_category", "REQUIRES_REVIEW")
                    r_level = f.get("risk_level", "LOW")
                    badge_icon = "🟢" if cat == "POTENTIALLY_EXPECTED" else ("🟠" if cat == "PURPOSE_MISMATCH" else "🟡")
                    
                    with st.container(border=True):
                        st.markdown(f"#### {badge_icon} `{f.get('permission')}` — **{cat.replace('_', ' ')}** ({r_level} Risk)")
                        st.markdown(f"**Reason:** {f.get('reason')}")
                        st.markdown(f"**Privacy Implication:** {f.get('privacy_implication')}")
                        st.markdown(f"**Purpose Comparison:** {f.get('purpose_comparison')}")
                        if f.get("review_question"):
                            st.info(f"❓ **Review Question:** {f.get('review_question')}")
                        st.caption(f"Source: `{f.get('evidence_source')}` ({f.get('source_reference')}) | Confidence: `{f.get('confidence')}`")
            else:
                st.info("No purpose comparison findings recorded.")

    # SECTION 4: Interactive Permission Deep Dive Matrix
    st.markdown("### 4. 🛡️ Permission Explainability Deep Dive")
    filter_choice = st.radio(
        "Filter Permissions By Classification:",
        ["All Permissions", "Dangerous Only", "Special Only", "Normal Only", "Unknown Only"],
        horizontal=True
    )

    filtered_perms = permissions
    if filter_choice == "Dangerous Only":
        filtered_perms = [p for p in permissions if p.get("protection_level") == "dangerous"]
    elif filter_choice == "Special Only":
        filtered_perms = [p for p in permissions if p.get("protection_level") in ("special", "signature/special")]
    elif filter_choice == "Normal Only":
        filtered_perms = [p for p in permissions if p.get("protection_level") == "normal"]
    elif filter_choice == "Unknown Only":
        filtered_perms = [p for p in permissions if p.get("protection_level") == "unknown"]

    if filtered_perms:
        for p in filtered_perms:
            prot = p.get("protection_level", "normal")
            prot_color = "red" if prot in ("dangerous", "special") else ("green" if prot == "normal" else "gray")
            with st.expander(f"**{p.get('short_name')}** ({p.get('group', 'General')}) — :{prot_color}[{prot.upper()}] — Severity: {p.get('severity_score', 1.0)}/10"):
                st.markdown(f"**Exact Identifier:** `{p.get('name')}`")
                
                src_ref = p.get("source_reference")
                if src_ref:
                    st.caption(f"Manifest XPath Reference: `{src_ref}`")

                st.markdown(f"**Capability Description:** {p.get('description')}")
                
                exp_text = p.get("explanation")
                if exp_text:
                    st.info(f"💡 **Explainability Note:** {exp_text}")
                
                st.markdown(f"**Privacy Threat Impact:** {p.get('privacy_risk')}")
                
                sens_data = p.get("sensitive_data", [])
                if sens_data:
                    st.markdown(f"**Sensitive Data Categories:** `{', '.join(sens_data)}`")

                plat_ctx = p.get("platform_context")
                if plat_ctx:
                    st.markdown(f"**Platform Context & OS Architecture:** {plat_ctx}")
                
                scenarios = p.get("abuse_scenarios", [])
                if scenarios:
                    st.markdown("**Real-World Abuse Scenarios:**")
                    for s in scenarios:
                        st.markdown(f"- {s}")
                
                st.markdown(f"**Developer Best-Practice Remediation:** `{p.get('remediation')}`")
                
                doc_url = p.get("documentation_url")
                if doc_url:
                    st.markdown(f"🔗 [Official Android Documentation Reference]({doc_url})")
                
                disc_status = p.get("discrepancy_status", "NORMAL")
                if disc_status != "NORMAL":
                    st.caption(f"Policy Status Flag: **{disc_status}**")
    else:
        st.info("No permissions found matching the selected filter.")

    # SECTION 5: Target SDK & Component Attack Surface
    st.markdown("### 5. ⚙️ Component Exposure & Sandbox Security Posture")
    sdk_warnings = data.get("target_sdk_warnings", [])
    if sdk_warnings:
        for w in sdk_warnings:
            st.warning(f"⚠️ {w}")
    else:
        st.success(f"✓ Target SDK `{data.get('target_sdk')}` complies with modern Android runtime sandbox guarantees.")

    st.markdown("---")
    if st.button("⬅️ Run Another Audit", use_container_width=True):
        set_page("New Analysis")
