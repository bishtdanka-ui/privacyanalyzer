import streamlit as st
from frontend.api_client import api_client
from frontend.state import login_user

def render_auth_view():
    st.markdown("<h1 style='text-align: center; color: #1e88e5;'>🛡️ Explainable Privacy & Permission Analyzer</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #90a4ae;'>Problem Statement: Cybersecurity / Application Privacy / Explainable Security (PS02)</p>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        tab_login, tab_register = st.tabs(["🔐 Secure Sign In", "📝 Create Analyst Account"])

        with tab_login:
            st.subheader("Platform Access")
            with st.form("login_form"):
                ident = st.text_input("Username or Email", placeholder="admin@privacyanalyzer.local or analyst")
                pwd = st.text_input("Password", type="password")
                submitted = st.form_submit_button("Sign In", use_container_width=True)

                if submitted:
                    if not ident or not pwd:
                        st.error("Please enter both username/email and password.")
                    else:
                        with st.spinner("Authenticating against secure backend..."):
                            success, resp = api_client.login(ident, pwd)
                            if success:
                                token = resp["access_token"]
                                user = resp["user"]
                                login_user(token, user)
                                st.success(f"Welcome back, {user.get('username')}!")
                                st.rerun()
                            else:
                                st.error(str(resp))

            # Demo credentials hint box
            with st.expander("ℹ️ Hackathon Evaluator Default Credentials", expanded=True):
                st.markdown("""
                - **Administrator:** `admin@privacyanalyzer.local` | `AdminSecurePassword123!`
                - *Or register a new analyst user account on the second tab.*
                """)

        with tab_register:
            st.subheader("New Analyst Registration")
            with st.form("register_form"):
                reg_email = st.text_input("Email Address", placeholder="analyst@domain.com")
                reg_user = st.text_input("Username", placeholder="analyst_name")
                reg_name = st.text_input("Full Name (Optional)", placeholder="Security Researcher")
                reg_pass = st.text_input("Password (min 8 characters)", type="password")
                reg_pass2 = st.text_input("Confirm Password", type="password")
                reg_submitted = st.form_submit_button("Create Account", use_container_width=True)

                if reg_submitted:
                    if not reg_email or not reg_user or not reg_pass:
                        st.error("Please fill in all required fields.")
                    elif reg_pass != reg_pass2:
                        st.error("Passwords do not match.")
                    elif len(reg_pass) < 8:
                        st.error("Password must be at least 8 characters.")
                    else:
                        with st.spinner("Registering user in persistent database..."):
                            success, resp = api_client.register(reg_email, reg_user, reg_name, reg_pass)
                            if success:
                                st.success("Account registered successfully! Please sign in using your credentials.")
                            else:
                                st.error(str(resp))
