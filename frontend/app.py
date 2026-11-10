"""
PrivacyGuard — Explainable Application Privacy & Permission Analyzer
Main Application Entrypoint & Layout Router
"""

import streamlit as st
from frontend.auth_client import auth_client
from frontend.state import init_session_state, is_authenticated, is_admin, logout_user, set_page
from frontend.theme import inject_cyber_theme, render_brand_header
from frontend.views.auth_view import render_auth_view
from frontend.views.dashboard_view import render_dashboard_view
from frontend.views.analyzer_view import render_analyzer_view
from frontend.views.results_view import render_results_view
from frontend.views.history_view import render_history_view
from frontend.views.profile_view import render_profile_view
from frontend.views.admin_view import render_admin_view

st.set_page_config(
    page_title="PrivacyGuard — Explainable Application Privacy Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply global cybersecurity styling
inject_cyber_theme()

# Initialize session state variables
init_session_state()

def main():
    # Authoritative session synchronization with FastAPI backend
    if st.session_state.get("token") and not auth_client.sync_session():
        auth_client.clear_session()

    if not is_authenticated():
        render_auth_view()
        return

    user = st.session_state.get("user", {})
    admin_access = is_admin()

    # Sidebar Navigation
    with st.sidebar:
        st.markdown("## 🛡️ **PrivacyGuard**")
        st.caption("Explainable Application Privacy & Permission Analyzer — PS02")
        st.divider()

        user_name = user.get("full_name") or user.get("email", "Analyst")
        st.markdown(f"👤 **Analyst:** `{user_name}`")
        role_badge = "👑 Administrator" if admin_access else "🔬 Security Analyst"
        st.markdown(f"🏷️ **Access:** {role_badge}")
        st.divider()

        # Navigation Options
        pages = ["Dashboard", "New Analysis"]
        if st.session_state.get("active_analysis"):
            pages.append("Results")
        pages.extend(["History", "Profile"])
        if admin_access:
            pages.append("Admin Console")

        current = st.session_state.get("current_page", "Dashboard")
        if current not in pages:
            current = "Dashboard"

        nav_selection = st.radio("Navigation Menu", pages, index=pages.index(current), label_visibility="collapsed")
        if nav_selection != current:
            set_page(nav_selection)

        st.divider()
        st.caption("🔒 Session secured via Argon2id & rotating JWT")
        if st.button("🚪 Sign Out", use_container_width=True):
            logout_user()

    # Page Router
    active_page = st.session_state.get("current_page", "Dashboard")

    if active_page == "Dashboard":
        render_dashboard_view()
    elif active_page == "New Analysis":
        render_analyzer_view()
    elif active_page == "Results":
        render_results_view()
    elif active_page == "History":
        render_history_view()
    elif active_page == "Profile":
        render_profile_view()
    elif active_page == "Admin Console" and admin_access:
        render_admin_view()
    else:
        render_dashboard_view()

if __name__ == "__main__":
    main()
