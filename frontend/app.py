import streamlit as st
from frontend.state import init_session_state, is_authenticated, is_admin, logout_user, set_page
from frontend.views.auth_view import render_auth_view
from frontend.views.dashboard_view import render_dashboard_view
from frontend.views.analyzer_view import render_analyzer_view
from frontend.views.results_view import render_results_view
from frontend.views.history_view import render_history_view
from frontend.views.admin_view import render_admin_view

st.set_page_config(
    page_title="Explainable Privacy & Permission Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cybersecurity Design Styling
st.markdown("""
<style>
    .main {
        background-color: #0b0f19;
    }
    .stMetric {
        background: #111827;
        padding: 12px;
        border-radius: 8px;
        border: 1px solid #1f2937;
    }
    div[data-testid="stExpander"] {
        border: 1px solid #1f2937;
        border-radius: 6px;
    }
    .badge-critical {
        color: #ff5252;
        font-weight: bold;
    }
    .badge-high {
        color: #ff9100;
        font-weight: bold;
    }
    .badge-medium {
        color: #ffd600;
        font-weight: bold;
    }
    .badge-low {
        color: #00e676;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

init_session_state()

def main():
    if not is_authenticated():
        render_auth_view()
        return

    # Authenticated user view
    user = st.session_state.get("user", {})
    admin_access = is_admin()

    # Sidebar Navigation
    with st.sidebar:
        st.markdown("### 🛡️ Privacy Analyzer")
        st.caption("Explainable Security PS02")
        st.divider()

        st.markdown(f"**Analyst:** `{user.get('username')}`")
        role_label = "👑 Administrator" if admin_access else "🔬 Security Analyst"
        st.markdown(f"**Role:** {role_label}")
        st.divider()

        pages = ["Dashboard", "Privacy Analyzer", "Audit History"]
        if st.session_state.get("active_analysis"):
            pages.insert(2, "Results")
        if admin_access:
            pages.append("Admin Console")

        current = st.session_state.get("current_page", "Dashboard")
        if current not in pages:
            current = "Dashboard"

        nav_selection = st.radio("Navigation", pages, index=pages.index(current))
        if nav_selection != current:
            set_page(nav_selection)

        st.divider()
        if st.button("🚪 Sign Out", use_container_width=True):
            logout_user()

    # Page Router
    active_page = st.session_state.get("current_page", "Dashboard")

    if active_page == "Dashboard":
        render_dashboard_view()
    elif active_page == "Privacy Analyzer":
        render_analyzer_view()
    elif active_page == "Results":
        render_results_view()
    elif active_page == "Audit History":
        render_history_view()
    elif active_page == "Admin Console" and admin_access:
        render_admin_view()
    else:
        render_dashboard_view()

if __name__ == "__main__":
    main()
