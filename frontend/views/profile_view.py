"""
PrivacyGuard — Analyst Profile & Security Settings View
User account credentials, password changes, active session tokens, and sign out controls.
"""

import streamlit as st
import pandas as pd
from frontend.api_client import api_client
from frontend.state import logout_user
from frontend.theme import render_brand_header

def render_profile_view():
    token = st.session_state.get("token")
    user = st.session_state.get("user", {})

    render_brand_header(
        title="👤 Analyst Profile & Security Settings",
        subtitle="Manage your authentication credentials, update analyst details, and audit active login sessions."
    )

    col_details, col_pwd = st.columns([1, 1])

    with col_details:
        st.subheader("Analyst Account Details")
        with st.container(border=True):
            with st.form("profile_update_form"):
                st.text_input("Registered Email Address", value=user.get("email"), disabled=True)
                new_name = st.text_input("Full Name", value=user.get("full_name") or "")
                
                role = user.get("role", "user")
                role_label = "👑 Administrator (Full Platform Access)" if role == "admin" else "🔬 Security Analyst (Standard Access)"
                st.text_input("Security Role & RBAC Tier", value=role_label, disabled=True)
                
                st.caption(f"Tenant Account ID: `{user.get('id')}` | Account Active: `{'True' if user.get('is_active') else 'False'}`")
                
                submit_profile = st.form_submit_button("Update Analyst Name", type="primary", use_container_width=True)
                if submit_profile:
                    with st.spinner("Persisting profile changes to database..."):
                        success, resp = api_client.update_profile(new_name, None, token)
                        if success:
                            st.session_state["user"] = resp
                            st.success("Profile updated successfully in database!")
                            st.rerun()
                        else:
                            st.error(f"Failed to update profile: {resp}")

    with col_pwd:
        st.subheader("Credential Rotation (Argon2id)")
        with st.container(border=True):
            with st.form("password_change_form"):
                old_pass = st.text_input("Current Master Password", type="password")
                new_pass = st.text_input("New Password (min 8 characters)", type="password")
                confirm_pass = st.text_input("Confirm New Password", type="password")
                
                submit_pass = st.form_submit_button("Rotate Password", use_container_width=True)
                if submit_pass:
                    if not old_pass or not new_pass:
                        st.error("Please provide both current and new passwords.")
                    elif new_pass != confirm_pass:
                        st.error("New passwords do not match.")
                    elif len(new_pass) < 8:
                        st.error("New password must be at least 8 characters long.")
                    else:
                        with st.spinner("Hashing with Argon2id and rotating credentials..."):
                            success, resp = api_client.change_password(old_pass, new_pass, token)
                            if success:
                                st.success("Password changed successfully!")
                            else:
                                st.error(f"Error: {resp}")

    st.markdown("---")

    # Session Management
    st.subheader("🔐 Active Authenticated Sessions (`user_sessions` Table)")
    st.caption("Active refresh tokens tracked in database with automatic session expiration.")
    with st.spinner("Loading active session telemetry..."):
        success_s, sessions = api_client.get_sessions(token)
        if success_s and sessions:
            df_sessions = pd.DataFrame(sessions)
            df_sessions.rename(columns={
                "id": "Session ID",
                "ip_address": "IP Address",
                "user_agent": "Client Software / Browser",
                "is_active": "Active",
                "created_at": "Logged In At",
                "expires_at": "Expires At"
            }, inplace=True)
            st.dataframe(df_sessions, use_container_width=True, hide_index=True)
        else:
            st.info("No recorded sessions found.")

    st.markdown("---")
    st.subheader("🚪 Account Session Termination")
    st.caption("Revoke current authentication token and clear local session state.")
    if st.button("🚪 Sign Out of PrivacyGuard Portal", type="secondary", use_container_width=True):
        logout_user()
