import streamlit as st
import re
from frontend.api_client import api_client
from frontend.state import login_user

def calculate_password_strength(password: str):
    """
    Returns score (0-100), label, and list of requirement checks.
    """
    if not password:
        return 0, "Empty", []
    
    checks = [
        ("At least 8 characters", len(password) >= 8),
        ("At least one uppercase letter (A-Z)", bool(re.search(r"[A-Z]", password))),
        ("At least one lowercase letter (a-z)", bool(re.search(r"[a-z]", password))),
        ("At least one number (0-9)", bool(re.search(r"\d", password))),
        ("At least one special character (!@#$%...)", bool(re.search(r"[!@#$%^&*(),.?\":{}|<>\-_=+/\\\[\]~`]", password)))
    ]
    
    passed_count = sum(1 for _, ok in checks if ok)
    score = int((passed_count / 5.0) * 100)
    
    if passed_count <= 2:
        label = "Weak"
        color = "red"
    elif passed_count <= 4:
        label = "Moderate"
        color = "orange"
    else:
        label = "Strong (Argon2id Ready)"
        color = "green"
        
    return score, label, color, checks

def render_auth_view():
    st.markdown("<h1 style='text-align: center; color: #1e88e5;'>🛡️ Explainable Privacy & Permission Analyzer</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #90a4ae;'>Enterprise Application Security & Privacy Auditing — PS02</p>", unsafe_allow_html=True)
    st.write("")

    auth_mode = st.session_state.get("auth_mode", "login")

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if auth_mode == "login":
            render_login_card()
        else:
            render_register_card()

def render_login_card():
    with st.container(border=True):
        st.subheader("🔐 Secure Sign In")
        st.caption("Access the Security Operations Center with your analyst credentials.")

        # Email
        login_email = st.text_input("Corporate / Analyst Email", placeholder="analyst@domain.com", key="login_email_input")
        
        # Show/Hide password toggle
        show_pwd = st.checkbox("Show password", key="login_show_pwd")
        pwd_type = "default" if show_pwd else "password"
        login_pwd = st.text_input("Password", type=pwd_type, placeholder="Enter master password", key="login_pwd_input")
        
        # Remember-session option
        remember_me = st.checkbox("Remember session (extended 30-day token)", value=False, key="login_remember_me")

        st.write("")
        login_btn = st.button("Sign In to Portal", type="primary", use_container_width=True)

        if login_btn:
            if not login_email or not login_pwd:
                st.error("Please enter both email and password.")
            elif "@" not in login_email:
                st.error("Please provide a valid email format.")
            else:
                with st.spinner("Verifying credentials against Argon2id database..."):
                    success, resp = api_client.login(login_email, login_pwd, remember_me=remember_me)
                    if success:
                        access_token = resp["access_token"]
                        refresh_token = resp.get("refresh_token")
                        user = resp["user"]
                        login_user(access_token, user, refresh_token)
                        st.success("Authentication successful! Loading dashboard...")
                        st.rerun()
                    else:
                        st.error(f"❌ {resp}")

        st.divider()
        st.markdown("Don't have an analyst account yet?")
        if st.button("Create New Analyst Account →", use_container_width=True):
            st.session_state["auth_mode"] = "register"
            st.rerun()

    # Demo Credentials Hint
    with st.expander("ℹ️ Evaluator Default Administrator Account", expanded=False):
        st.markdown("""
        - **Admin Email:** `admin@privacyanalyzer.local`
        - **Password:** `AdminSecurePassword123!`
        - **Security:** Argon2id hash with rotating session refresh tokens
        """)

def render_register_card():
    with st.container(border=True):
        st.subheader("📝 Analyst Account Registration")
        st.caption("Register for authorized access to Android manifest & privacy evaluation.")

        reg_name = st.text_input("Full Name", placeholder="e.g. Jane Doe, Senior Analyst", key="reg_name_input")
        reg_email = st.text_input("Email Address", placeholder="analyst@organization.com", key="reg_email_input")
        
        show_reg_pwd = st.checkbox("Show password", key="reg_show_pwd")
        pwd_type = "default" if show_reg_pwd else "password"
        
        reg_password = st.text_input("Password", type=pwd_type, placeholder="Minimum 8 characters with upper, lower, digit & symbol", key="reg_pwd_input")
        reg_confirm = st.text_input("Confirm Password", type=pwd_type, placeholder="Re-type password", key="reg_confirm_input")

        # Password Strength Indicator
        if reg_password:
            score, label, color, checks = calculate_password_strength(reg_password)
            st.markdown(f"**Password Strength:** :{color}[**{label}**] ({score}%)")
            st.progress(score / 100.0)
            with st.expander("Password Security Requirements Checklist", expanded=(score < 100)):
                for desc, passed in checks:
                    icon = "✅" if passed else "❌"
                    st.markdown(f"{icon} {desc}")

        # Terms acceptance
        terms_accepted = st.checkbox("I accept the Application Privacy & Security Assessment Terms of Service", value=False, key="reg_terms")

        st.write("")
        register_btn = st.button("Complete Registration", type="primary", use_container_width=True)

        if register_btn:
            if not reg_email or not reg_password:
                st.error("Please fill in all required fields.")
            elif "@" not in reg_email:
                st.error("Please provide a valid email format.")
            elif reg_password != reg_confirm:
                st.error("Passwords do not match.")
            elif not terms_accepted:
                st.error("You must accept the terms of service to proceed.")
            else:
                score, label, color, _ = calculate_password_strength(reg_password)
                if score < 100:
                    st.error("Please ensure your password satisfies all 5 security requirements.")
                else:
                    with st.spinner("Generating Argon2id salt and hashing credentials..."):
                        success, resp = api_client.register(
                            email=reg_email,
                            full_name=reg_name,
                            password=reg_password,
                            terms_accepted=terms_accepted
                        )
                        if success:
                            st.success("Account successfully registered with Argon2id protection! You can now sign in.")
                            st.session_state["auth_mode"] = "login"
                            st.rerun()
                        else:
                            st.error(f"❌ {resp}")

        st.divider()
        st.markdown("Already have an account?")
        if st.button("← Back to Secure Sign In", use_container_width=True):
            st.session_state["auth_mode"] = "login"
            st.rerun()
