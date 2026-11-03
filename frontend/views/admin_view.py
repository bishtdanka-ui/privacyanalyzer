import streamlit as st
import pandas as pd
from frontend.api_client import api_client

def render_admin_view():
    st.markdown("## ⚙️ Platform Administration & Compliance Console")
    st.markdown("Global telemetry, user access control, and security audit log review.")
    st.divider()

    token = st.session_state.get("token")

    tab_stats, tab_users, tab_logs = st.tabs([
        "📈 System Telemetry & Risk Aggregates",
        "👥 User Access Management",
        "🔒 Security Audit Trail"
    ])

    with tab_stats:
        st.subheader("Cross-Application Security Telemetry")
        success, stats = api_client.get_admin_stats(token)
        if success:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Registered Users", stats.get("total_users", 0))
            c2.metric("Total App Audits", stats.get("total_analyses", 0))
            c3.metric("Critical Threats Found", stats.get("critical_risk_count", 0), delta_color="inverse")
            c4.metric("Avg Risk Score", f"{stats.get('average_risk_score', 0)}/100")

            st.markdown("#### 🚨 Top Requested Dangerous Permissions Across All Apps")
            top_perms = stats.get("top_dangerous_permissions", [])
            if top_perms:
                df_top = pd.DataFrame(top_perms)
                st.dataframe(df_top, use_container_width=True, hide_index=True)
            else:
                st.info("No permissions recorded in aggregated dataset yet.")
        else:
            st.error(f"Failed to fetch system stats: {stats}")

    with tab_users:
        st.subheader("User Account & RBAC Controls")
        success_u, users = api_client.get_admin_users(token)
        if success_u and users:
            df_users = pd.DataFrame(users)
            st.dataframe(
                df_users[["id", "email", "username", "role", "is_active", "created_at"]],
                use_container_width=True,
                hide_index=True
            )

            st.markdown("#### Modify User Status / Role")
            user_options = {f"{u['username']} (ID: {u['id']})": u for u in users}
            selected_label = st.selectbox("Select User to Manage:", list(user_options.keys()))
            target_user = user_options[selected_label]

            col_act1, col_act2 = st.columns(2)
            with col_act1:
                new_role = st.selectbox("Role Assignment:", ["user", "admin"], index=0 if target_user["role"] == "user" else 1)
                if st.button("Update Role", use_container_width=True):
                    s, resp = api_client.update_admin_user(target_user["id"], {"role": new_role}, token)
                    if s:
                        st.success(f"User role updated to '{new_role}'.")
                        st.rerun()
                    else:
                        st.error(str(resp))

            with col_act2:
                toggle_action = "Deactivate Account" if target_user["is_active"] else "Activate Account"
                target_state = not target_user["is_active"]
                if st.button(toggle_action, use_container_width=True):
                    s, resp = api_client.update_admin_user(target_user["id"], {"is_active": target_state}, token)
                    if s:
                        st.success(f"User account status updated.")
                        st.rerun()
                    else:
                        st.error(str(resp))
        else:
            st.error("Failed to load user list.")

    with tab_logs:
        st.subheader("Security Event & Audit Trail (Last 50 Events)")
        success_l, logs = api_client.get_admin_audit_logs(50, token)
        if success_l and logs:
            df_logs = pd.DataFrame(logs)
            display_cols = ["id", "action", "username", "target_type", "target_id", "ip_address", "created_at"]
            st.dataframe(df_logs[display_cols], use_container_width=True, hide_index=True)
        else:
            st.info("No audit logs available.")

