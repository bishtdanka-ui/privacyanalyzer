"""
PrivacyGuard — Authentication View
Secure Login & Registration Pages with Argon2id Password Strength Meter
"""

import streamlit as st
import re
from frontend.auth_client import auth_client
from frontend.theme import render_brand_header

def calculate_password_strength(password: str):
    """
    Returns score (0-100), label, color, and list of requirement checks.
    """
    if not password:
        return 0, "Empty", "gray", []
    
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
        label = "Strong (Argon2id Compliant)"
        color = "green"
        
    return score, label, color, checks

def render_auth_view():
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        render_brand_header(
            title="🛡️ PrivacyGuard",
            subtitle="Explainable Application Privacy & Permission Risk Analyzer — PS02"
        )
        
        auth_mode = st.session_state.get("auth_mode", "login")
        if auth_mode == "login":
            render_login_card()
        else:
            render_register_card()

def render_login_card():
    with st.container(border=True):
        st.subheader("🔐 Analyst Portal Sign In")
        st.caption("Access the Security Operations Center with your authenticated credentials.")

        login_email = st.text_input("Analyst / Corporate Email", placeholder="analyst@organization.com", key="login_email_input")
        
        show_pwd = st.checkbox("Show password", key="login_show_pwd")
        pwd_type = "default" if show_pwd else "password"
        login_pwd = st.text_input("Password", type=pwd_type, placeholder="Enter master password", key="login_pwd_input")
        
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
                    success, resp = auth_client.login(login_email, login_pwd, remember_me=remember_me)
                    if success:
                        st.success("Authentication successful! Loading dashboard...")
                        st.rerun()
                    else:
                        st.error(f"❌ {resp}")

        st.divider()
        st.markdown("Don't have an analyst account yet?")
        if st.button("Create New Analyst Account →", use_container_width=True):
            st.session_state["auth_mode"] = "register"
            st.rerun()

    # Enterprise Authentication Security Posture Notice
    with st.expander("ℹ️ Enterprise Authentication & Security Posture", expanded=False):
        st.markdown("""
        - **Cryptographic Hashing:** Argon2id with cryptographically random per-user salt.
        - **Session Tokens:** Short-lived access JWTs with rotating refresh tokens stored in database.
        - **Zero Client Trust:** Authentication and role enforcement are governed strictly by the backend authority.
        """)

def render_register_card():
    with st.container(border=True):
        st.subheader("📝 Analyst Account Registration")
        st.caption("Register for authorized access to Android privacy audit workflows.")

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

        terms_accepted = st.checkbox("I accept the PrivacyGuard Security & Privacy Assessment Terms", value=False, key="reg_terms")

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
                score, _, _, _ = calculate_password_strength(reg_password)
                if score < 60:
                    st.warning("Password does not meet minimum complexity standards. Please include upper, lower, numbers, and symbols.")
                else:
                    with st.spinner("Hashing with Argon2id and registering account..."):
                        success, resp = auth_client.register(
                            email=reg_email,
                            full_name=reg_name,
                            password=reg_password,
                            terms_accepted=terms_accepted
                        )
                        if success:
                            st.success("Account created successfully! Please sign in with your credentials.")
                            st.session_state["auth_mode"] = "login"
                            st.rerun()
                        else:
                            st.error(f"❌ {resp}")

        st.divider()
        st.markdown("Already have an analyst account?")
        if st.button("← Back to Sign In", use_container_width=True):
            st.session_state["auth_mode"] = "login"
            st.rerun()
