import streamlit as st
import pandas as pd
from frontend.api_client import api_client

def render_profile_view():
    token = st.session_state.get("token")
    user = st.session_state.get("user", {})

    st.markdown("## 👤 Analyst Profile & Security Settings")
    st.markdown("Manage your security analyst credentials, account details, and active login sessions.")
    st.divider()

    col1, col2 = st.columns([1, 1])

    with col1:
        st.subheader("Account Details")
        with st.form("profile_update_form"):
            st.text_input("Username", value=user.get("username"), disabled=True)
            new_name = st.text_input("Full Name", value=user.get("full_name") or "")
            new_email = st.text_input("Email Address", value=user.get("email") or "")
            role_label = "Administrator (Full Access)" if user.get("role") == "admin" else "Security Analyst (Standard Access)"
            st.text_input("Role & Privileges", value=role_label, disabled=True)
            
            submit_profile = st.form_submit_button("Update Profile Information", type="primary", use_container_width=True)
            if submit_profile:
                with st.spinner("Updating profile in database..."):
                    success, resp = api_client.update_profile(new_name, new_email, token)
                    if success:
                        st.session_state["user"] = resp
                        st.success("Profile updated successfully!")
                        st.rerun()
                    else:
                        st.error(f"Failed to update profile: {resp}")

    with col2:
        st.subheader("Security & Password")
        with st.form("password_change_form"):
            old_pass = st.text_input("Current Password", type="password")
            new_pass = st.text_input("New Password (min 8 characters)", type="password")
            confirm_pass = st.text_input("Confirm New Password", type="password")
            
            submit_pass = st.form_submit_button("Change Password", use_container_width=True)
            if submit_pass:
                if not old_pass or not new_pass:
                    st.error("Please provide both current and new passwords.")
                elif new_pass != confirm_pass:
                    st.error("New passwords do not match.")
                elif len(new_pass) < 8:
                    st.error("New password must be at least 8 characters.")
                else:
                    with st.spinner("Verifying and changing password..."):
                        success, resp = api_client.change_password(old_pass, new_pass, token)
                        if success:
                            st.success("Password changed successfully!")
                        else:
                            st.error(f"Error: {resp}")

    st.markdown("---")
    st.subheader("🔐 Active Authenticated Sessions (`user_sessions` Table)")
    with st.spinner("Loading active session records..."):
        success_s, sessions = api_client.get_sessions(token)
        if success_s and sessions:
            df_sessions = pd.DataFrame(sessions)
            df_sessions.rename(columns={
                "id": "Session ID",
                "ip_address": "IP Address",
                "user_agent": "Client / Device",
                "is_active": "Active",
                "created_at": "Logged In At",
                "expires_at": "Expires At"
            }, inplace=True)
            st.dataframe(df_sessions, use_container_width=True, hide_index=True)
        else:
            st.info("No recorded sessions found.")
