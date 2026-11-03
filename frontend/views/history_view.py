import streamlit as st
import pandas as pd
from frontend.api_client import api_client
from frontend.state import set_page

def render_history_view():
    st.markdown("## 📜 Audit History & Persistent Records")
    st.markdown("Review all previous application privacy evaluations stored securely in the database.")
    st.divider()

    token = st.session_state.get("token")
    success, history_data = api_client.get_history(token)

    if not success or not history_data:
        st.info("No prior analysis records found. Run an audit from the Privacy Analyzer tab to create persistent records.")
        if st.button("Launch New Audit"):
            set_page("New Analysis")
        return

    # Filter by risk level
    risk_filter = st.selectbox("Filter History by Risk Level:", ["All Records", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    filtered_data = history_data
    if risk_filter != "All Records":
        filtered_data = [h for h in history_data if h.get("risk_level") == risk_filter]

    st.markdown(f"Displaying **{len(filtered_data)}** audit records:")

    for record in filtered_data:
        r_id = record["id"]
        app_name = record["app_name"]
        pkg = record["package_name"]
        r_level = record["risk_level"]
        r_score = record["risk_score"]
        created = record["created_at"]
        dangerous = record["dangerous_count"]

        badge_color = {
            "CRITICAL": "red",
            "HIGH": "orange",
            "MEDIUM": "yellow",
            "LOW": "green"
        }.get(r_level, "blue")

        with st.container(border=True):
            col1, col2, col3, col4 = st.columns([3, 2, 2, 2])
            with col1:
                st.markdown(f"**{app_name}**")
                st.caption(f"Package: `{pkg}`")
            with col2:
                st.markdown(f":{badge_color}[**{r_level} ({r_score}/100)**]")
                st.caption(f"Dangerous Perms: **{dangerous}**")
            with col3:
                st.caption(f"Date: {created[:19].replace('T', ' ')}")
            with col4:
                btn_col1, btn_col2 = st.columns(2)
                with btn_col1:
                    if st.button("👁️ View", key=f"view_{r_id}", use_container_width=True):
                        s, full_data = api_client.get_analysis_details(r_id, token)
                        if s:
                            st.session_state["active_analysis"] = full_data
                            set_page("Results")
                        else:
                            st.error(str(full_data))
                with btn_col2:
                    if st.button("🗑️", key=f"del_{r_id}", use_container_width=True):
                        s, del_msg = api_client.delete_analysis(r_id, token)
                        if s:
                            st.success("Record deleted.")
                            st.rerun()
                        else:
                            st.error(str(del_msg))

