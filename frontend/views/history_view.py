"""
PrivacyGuard — Audit History View
Persistent analysis records, real-time search, risk filters, inspection, and secure deletion.
"""

import streamlit as st
import pandas as pd
from frontend.api_client import api_client
from frontend.state import set_page
from frontend.theme import render_brand_header, get_risk_badge_html

def render_history_view():
    render_brand_header(
        title="📜 Persistent Audit Records & History",
        subtitle="Search, filter, inspect, and manage historical application privacy evaluations stored in the database."
    )

    token = st.session_state.get("token")
    with st.spinner("Fetching persistent analysis records from database..."):
        success, history_data = api_client.get_history(token)

    if not success or not history_data:
        st.info("No prior analysis records found in database. Run an audit from the New Analysis wizard to populate history.")
        if st.button("🚀 Launch First Audit", type="primary"):
            set_page("New Analysis")
        return

    # Search and Filter Toolbar
    col_search, col_filter = st.columns([3, 2])
    with col_search:
        search_query = st.text_input("🔍 Search by Application Name or Package ID:", placeholder="e.g. calculator, messenger, com.example...", key="hist_search")
    with col_filter:
        risk_filter = st.selectbox("Filter by Risk Level:", ["All Records", "CRITICAL", "HIGH", "MEDIUM", "LOW"], key="hist_filter")

    # Apply filters
    filtered = history_data
    if search_query and search_query.strip():
        q = search_query.strip().lower()
        filtered = [
            h for h in filtered
            if q in h.get("app_name", "").lower() or q in h.get("package_name", "").lower()
        ]

    if risk_filter != "All Records":
        filtered = [h for h in filtered if h.get("risk_level") == risk_filter]

    st.caption(f"Showing **{len(filtered)}** of **{len(history_data)}** persistent audit records.")

    if not filtered:
        st.warning("No records matched your search and filter criteria.")
        return

    # Render History Cards
    for record in filtered:
        r_id = record["id"]
        app_name = record["app_name"]
        pkg = record["package_name"]
        r_level = record["risk_level"]
        r_score = record.get("risk_score", 0.0)
        created = record.get("created_at", "")
        formatted_date = created[:19].replace("T", " ") if created else "Unknown"
        dangerous = record.get("dangerous_count", 0)
        total_p = record.get("total_permissions", 0)

        badge_html = get_risk_badge_html(r_level)

        with st.container(border=True):
            col_info, col_risk, col_meta, col_acts = st.columns([3, 2, 2, 2])
            with col_info:
                st.markdown(f"#### {app_name}")
                st.caption(f"Package: `{pkg}`")
            with col_risk:
                st.markdown(badge_html, unsafe_allow_html=True)
                st.caption(f"Risk Score: **{r_score}/100**")
            with col_meta:
                st.markdown(f"**Permissions:** {total_p} ({dangerous} dangerous)")
                st.caption(f"📅 {formatted_date}")
            with col_acts:
                col_btn1, col_btn2 = st.columns(2)
                with col_btn1:
                    if st.button("👁️ View", key=f"hist_view_{r_id}", use_container_width=True):
                        with st.spinner("Loading audit report..."):
                            s, details = api_client.get_analysis_details(r_id, token)
                            if s:
                                st.session_state["active_analysis"] = details
                                set_page("Results")
                            else:
                                st.error(str(details))
                with col_btn2:
                    # Delete with confirmation
                    with st.popover("🗑️ Delete"):
                        st.markdown(f"Permanently delete audit record for **{app_name}**?")
                        if st.button("Confirm Delete", key=f"hist_del_conf_{r_id}", type="primary"):
                            s, del_msg = api_client.delete_analysis(r_id, token)
                            if s:
                                st.success("Audit deleted.")
                                st.rerun()
                            else:
                                st.error(str(del_msg))
