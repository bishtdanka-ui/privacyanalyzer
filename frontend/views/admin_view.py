"""
PrivacyGuard — Administrator Dashboard & Security Governance Console
Problem Statement: PS02 - Explainable Cybersecurity Application Privacy & Permission Analyzer

Features:
1. Executive Telemetry & Application Health Monitor
2. User Access & RBAC Management (Paginated, Searchable, Activate/Deactivate)
3. Cross-Platform Analysis Activity Monitor
4. Permission Knowledge Base Review & Governance (Schema validation, publishing, documentation preservation)
5. Security Audit Log Trail (Paginated with action filtering)
"""

import json
import streamlit as st
import pandas as pd
from frontend.api_client import api_client
from frontend.theme import get_risk_badge_html


def render_admin_view():
    st.markdown("## ⚙️ Platform Administration & Security Governance Console")
    st.caption("Global cybersecurity telemetry, RBAC access governance, analysis monitoring, and permission knowledge base curation.")
    st.divider()

    token = st.session_state.get("token")
    if not token:
        st.error("Admin authentication session missing. Please re-authenticate.")
        return

    admin_tabs = st.tabs([
        "📈 System Telemetry & Health",
        "👥 User Management & RBAC",
        "🔍 Cross-Platform Analysis Monitor",
        "📚 Knowledge Base Governance",
        "🔒 Security Audit Trail"
    ])

    # =========================================================================
    # TAB 1: SYSTEM TELEMETRY & APPLICATION HEALTH
    # =========================================================================
    with admin_tabs[0]:
        st.subheader("Platform Telemetry & Security Health Monitor")
        success_stats, stats = api_client.get_admin_stats(token)

        if success_stats:
            # Row 1: User & Analysis Overview Metrics
            c1, c2, c3, c4, c5 = st.columns(5)
            c1.metric("Total Registered Users", stats.get("total_users", 0))
            c2.metric("Active Users", stats.get("active_users", 0))
            c3.metric("Total Analyses", stats.get("total_analyses", 0))
            c4.metric("Critical Risk Apps", stats.get("critical_risk_count", 0), delta_color="inverse")
            c5.metric("Avg Risk Index", f"{stats.get('average_risk_score', 0):.1f}/100")

            st.markdown("---")

            # Row 2: Permission Detection Statistics
            st.markdown("#### 🔬 Global Permission Detection Telemetry")
            perm_stats = stats.get("permission_statistics", {})
            p1, p2, p3, p4, p5 = st.columns(5)
            p1.metric("Total Detected", perm_stats.get("total_permissions_detected", 0))
            p2.metric("Dangerous Perms", perm_stats.get("dangerous_count", 0), delta_color="inverse")
            p3.metric("Normal Perms", perm_stats.get("normal_count", 0))
            p4.metric("Special Perms", perm_stats.get("special_count", 0))
            p5.metric("Unknown Perms", perm_stats.get("unknown_count", 0), delta_color="inverse" if perm_stats.get("unknown_count", 0) > 0 else "normal")

            # Row 3: Two-Column Data Display
            col_left, col_right = st.columns([1, 1])

            with col_left:
                st.markdown("##### 🚨 Most Frequent Dangerous Permissions")
                top_perms = stats.get("top_dangerous_permissions", [])
                if top_perms:
                    df_top = pd.DataFrame(top_perms)
                    df_top.columns = ["Permission Identifier", "Detections"]
                    st.dataframe(df_top, use_container_width=True, hide_index=True)
                else:
                    st.info("No permissions recorded in telemetry yet.")

            with col_right:
                st.markdown("##### ⚠️ Detected Unknown / Non-Standard Permissions")
                top_unknown = perm_stats.get("top_unknown_permissions", [])
                if top_unknown:
                    df_unk = pd.DataFrame(top_unknown)
                    df_unk.columns = ["Permission Identifier", "Source Reference", "Detections"]
                    st.dataframe(df_unk, use_container_width=True, hide_index=True)
                else:
                    st.success("✓ Zero unknown permissions recorded across platform analyses.")

            st.markdown("---")

            # Row 4: Application Health Monitor
            st.markdown("#### 🏥 Application Subsystem Health")
            success_health, health = api_client.get_admin_health(token)
            if success_health:
                h1, h2, h3, h4 = st.columns(4)
                h1.metric("System Status", health.get("status", "UNKNOWN"))
                h2.metric("Database Engine", f"{health.get('database', {}).get('dialect', 'sqlite').upper()} ({health.get('database', {}).get('status', 'OK')})")
                h3.metric("Knowledge Base", f"v{health.get('knowledge_base', {}).get('version', '1.0')} ({health.get('knowledge_base', {}).get('entries_count', 0)} entries)")
                h4.metric("Storage Status", f"{'Writable' if health.get('storage', {}).get('writable') else 'Read-Only'} ({health.get('storage', {}).get('total_reports', 0)} reports)")
            else:
                st.warning("Application health subsystem detail unavailable.")
        else:
            st.error(f"Failed to fetch system telemetry: {stats}")

    # =========================================================================
    # TAB 2: USER MANAGEMENT & RBAC
    # =========================================================================
    with admin_tabs[1]:
        st.subheader("User Account Management & Role-Based Access Control (RBAC)")

        # Filter and Search Bar
        f_col1, f_col2, f_col3 = st.columns([2, 1, 1])
        with f_col1:
            user_search = st.text_input("🔍 Search Users:", placeholder="Search by email or name...")
        with f_col2:
            role_filter = st.selectbox("Filter Role:", ["All Roles", "user", "admin"])
        with f_col3:
            status_filter = st.selectbox("Filter Status:", ["All Statuses", "Active", "Deactivated"])

        clean_role = None if role_filter == "All Roles" else role_filter
        clean_status = None if status_filter == "All Statuses" else (True if status_filter == "Active" else False)

        user_page = st.number_input("User Page:", min_value=1, value=1, step=1, key="admin_user_page")
        success_u, user_resp = api_client.get_admin_users(
            token=token,
            page=user_page,
            page_size=10,
            search=user_search if user_search.strip() else None,
            role=clean_role,
            is_active=clean_status
        )

        if success_u and isinstance(user_resp, dict):
            users = user_resp.get("items", [])
            total_users_count = user_resp.get("total", 0)
            total_pages = user_resp.get("total_pages", 1)

            st.caption(f"Showing page {user_page} of {total_pages} ({total_users_count} total registered accounts)")

            if users:
                user_table_data = []
                for u in users:
                    user_table_data.append({
                        "ID": u["id"],
                        "Email": u["email"],
                        "Full Name": u.get("full_name") or "N/A",
                        "Role": "👑 Admin" if u["role"] == "admin" else "👤 User",
                        "Status": "🟢 Active" if u["is_active"] else "🔴 Deactivated",
                        "Analyses": u.get("total_analyses", 0),
                        "Registered At": u["created_at"][:19].replace("T", " ")
                    })
                st.dataframe(pd.DataFrame(user_table_data), use_container_width=True, hide_index=True)

                st.markdown("---")
                st.markdown("#### ⚡ Account Action & Permission Modification")

                user_options = {f"{u['email']} (ID: {u['id']} - {u['role'].upper()})": u for u in users}
                selected_label = st.selectbox("Select Target User Account:", list(user_options.keys()))
                target_user = user_options[selected_label]

                act_col1, act_col2 = st.columns(2)
                with act_col1:
                    new_role = st.selectbox(
                        "Assign Role:",
                        ["user", "admin"],
                        index=0 if target_user["role"] == "user" else 1,
                        key="role_sel"
                    )
                    if st.button("💾 Apply Role Change", use_container_width=True):
                        s, r = api_client.update_admin_user(target_user["id"], {"role": new_role}, token)
                        if s:
                            st.success(f"Role updated successfully to '{new_role}'.")
                            st.rerun()
                        else:
                            st.error(f"Failed to update role: {r}")

                with act_col2:
                    current_active = target_user["is_active"]
                    btn_label = "🔒 Deactivate User Account" if current_active else "🔓 Activate User Account"
                    btn_type = "secondary" if current_active else "primary"
                    target_active_state = not current_active

                    if st.button(btn_label, type=btn_type, use_container_width=True):
                        s, r = api_client.update_admin_user(target_user["id"], {"is_active": target_active_state}, token)
                        if s:
                            st.success(f"Account status updated to {'Active' if target_active_state else 'Deactivated'}.")
                            st.rerun()
                        else:
                            st.error(f"Action failed: {r}")
            else:
                st.info("No user accounts matched the filter criteria.")
        else:
            st.error(f"Failed to retrieve user accounts: {user_resp}")

    # =========================================================================
    # TAB 3: CROSS-PLATFORM ANALYSIS ACTIVITY MONITOR
    # =========================================================================
    with admin_tabs[2]:
        st.subheader("Global Application Analysis Activity Stream")
        st.caption("Monitor privacy assessments executed across all analyst accounts.")

        an_col1, an_col2 = st.columns([2, 1])
        with an_col1:
            an_search = st.text_input("🔍 Search Analyses:", placeholder="Search by app or package name...", key="an_search")
        with an_col2:
            an_risk = st.selectbox("Filter Risk:", ["All Risks", "CRITICAL", "HIGH", "MEDIUM", "LOW"], key="an_risk")

        clean_an_risk = None if an_risk == "All Risks" else an_risk
        an_page = st.number_input("Analysis Page:", min_value=1, value=1, step=1, key="admin_an_page")

        success_an, an_resp = api_client.get_admin_analyses(
            token=token,
            page=an_page,
            page_size=10,
            search=an_search if an_search.strip() else None,
            risk_level=clean_an_risk
        )

        if success_an and isinstance(an_resp, dict):
            analyses = an_resp.get("items", [])
            total_an = an_resp.get("total", 0)
            st.caption(f"Showing page {an_page} ({total_an} total analysis records)")

            if analyses:
                an_table_data = []
                for a in analyses:
                    an_table_data.append({
                        "ID": a["id"],
                        "Application Name": a["app_name"],
                        "Package Identifier": a["package_name"],
                        "Analyst / Owner": a["user_email"],
                        "Risk Level": a["risk_level"],
                        "Risk Score": f"{a['risk_score']:.1f}/100",
                        "Total Perms": a["total_permissions"],
                        "Dangerous Perms": a["dangerous_count"],
                        "Analyzed At": a["created_at"][:19].replace("T", " ")
                    })
                st.dataframe(pd.DataFrame(an_table_data), use_container_width=True, hide_index=True)
            else:
                st.info("No analysis records found.")
        else:
            st.error(f"Failed to load analyses stream: {an_resp}")

    # =========================================================================
    # TAB 4: PERMISSION KNOWLEDGE BASE GOVERNANCE
    # =========================================================================
    with admin_tabs[3]:
        st.subheader("Curated Android Permission Knowledge Base Governance")
        st.caption("Review official platform capabilities, validate JSON schemas, and publish vetted permission explanations.")

        # Sub-tabs: Review Catalog vs. Publish Entry
        kb_sub1, kb_sub2 = st.tabs(["📖 Review Curated Catalog", "➕ Publish / Update Knowledge Base Entry"])

        with kb_sub1:
            kb_s1, kb_s2, kb_s3 = st.columns([2, 1, 1])
            with kb_s1:
                kb_search = st.text_input("🔍 Search Knowledge Base:", placeholder="Search identifier, description...", key="kb_s")
            with kb_s2:
                kb_cat = st.selectbox("Category:", ["All Categories", "Camera", "Microphone", "Location", "Contacts", "SMS", "Storage", "Network", "Sensors"], key="kb_c")
            with kb_s3:
                kb_risk = st.selectbox("Risk Level:", ["All Levels", "CRITICAL", "HIGH", "MEDIUM", "LOW"], key="kb_r")

            clean_kb_cat = None if kb_cat == "All Categories" else kb_cat
            clean_kb_risk = None if kb_risk == "All Levels" else kb_risk

            success_kb, kb_data = api_client.get_admin_knowledge_base(
                token=token,
                search=kb_search if kb_search.strip() else None,
                category=clean_kb_cat,
                risk_level=clean_kb_risk
            )

            if success_kb and isinstance(kb_data, dict):
                meta = kb_data.get("metadata", {})
                entries = kb_data.get("entries", [])

                m1, m2, m3, m4 = st.columns(4)
                m1.metric("KB Release Version", f"v{meta.get('version', '1.3.0')}")
                m2.metric("Curated Permissions", meta.get("total_entries", 0))
                m3.metric("Filtered Matches", len(entries))
                m4.metric("Integrity Checksum", meta.get("checksum", "VALID")[:8].upper())

                st.markdown("---")
                if entries:
                    for e in entries:
                        with st.expander(f"🔑 **{e.get('permission')}** — {e.get('display_name')} ({e.get('risk_level')})"):
                            col_e1, col_e2 = st.columns([2, 1])
                            with col_e1:
                                st.markdown(f"**Plain-Language Description:** {e.get('description')}")
                                st.markdown(f"**Platform Context:** {e.get('platform_context')}")
                                st.markdown(f"**Objective Explainability Statement:** <i>\"{e.get('explanation')}\"</i>", unsafe_allow_html=True)
                            with col_e2:
                                st.markdown(f"**Category:** `{e.get('category')}`")
                                st.markdown(f"**Protection Level:** `{e.get('protection_level')}`")
                                st.markdown(f"**Risk Rating:** `{e.get('risk_level')}`")
                                if e.get("documentation_url"):
                                    st.markdown(f"**Official Docs:** [Android Developer Reference]({e.get('documentation_url')})")

                            st.markdown("**Potential Privacy Implications:**")
                            for imp in e.get("privacy_implications", []):
                                st.markdown(f"- {imp}")

                            st.markdown(f"**Sensitive Data Exposed:** `{', '.join(e.get('sensitive_data', []))}`")
                else:
                    st.info("No knowledge base permissions matched your search criteria.")
            else:
                st.error(f"Failed to fetch knowledge base: {kb_data}")

        with kb_sub2:
            st.markdown("#### 📝 Author & Validate Knowledge Base Entry")
            st.caption("Enforces strict JSON schema validation and official documentation URL requirements before publishing.")

            with st.form("kb_entry_form"):
                fe_col1, fe_col2 = st.columns(2)
                with fe_col1:
                    new_perm_id = st.text_input("Permission Identifier *", placeholder="android.permission.POST_NOTIFICATIONS")
                    new_disp_name = st.text_input("Display Name *", placeholder="Post Notifications Access")
                    new_cat = st.text_input("Category *", placeholder="Notifications")
                    new_prot = st.selectbox("Protection Level *", ["dangerous", "normal", "special", "signature", "privileged", "unknown"])
                    new_risk = st.selectbox("Risk Level *", ["HIGH", "MEDIUM", "LOW", "CRITICAL", "NEGLIGIBLE"])

                with fe_col2:
                    new_doc_url = st.text_input("Official Documentation URL *", placeholder="https://developer.android.com/reference/android/Manifest.permission#POST_NOTIFICATIONS")
                    new_sensitive = st.text_input("Sensitive Data Types (comma-separated) *", placeholder="Push Notifications, Alert Contents, Sender Metadata")
                    new_platform = st.text_area("Platform Context & Deprecation *", placeholder="Introduced in Android 13 (API level 33). Requires runtime authorization from user.")

                new_desc = st.text_area("Plain-Language Description *", placeholder="Allows an app to post notifications and display alerts to the user.")
                new_implications = st.text_area("Privacy Implications (one per line) *", placeholder="May display unsolicited advertisements.\nCould reveal sensitive notification summaries.")
                new_explanation = st.text_area("Objective Explainability Statement *", placeholder="The application declares permission to post notifications. Declaration alone does not establish message content.")

                val_submitted = st.form_submit_button("🧪 Validate JSON Schema & Requirements")

            if val_submitted:
                candidate = {
                    "permission": new_perm_id.strip(),
                    "category": new_cat.strip(),
                    "display_name": new_disp_name.strip(),
                    "description": new_desc.strip(),
                    "privacy_implications": [x.strip() for x in new_implications.strip().split("\n") if x.strip()],
                    "sensitive_data": [x.strip() for x in new_sensitive.strip().split(",") if x.strip()],
                    "protection_level": new_prot.strip().lower(),
                    "platform_context": new_platform.strip(),
                    "documentation_url": new_doc_url.strip(),
                    "risk_level": new_risk.strip().upper(),
                    "explanation": new_explanation.strip()
                }

                ok_val, val_resp = api_client.validate_kb_entry(candidate, token)
                if ok_val and val_resp.get("valid"):
                    st.success("✅ **JSON Schema Conformance Verified!** The entry complies with knowledge base standards.")
                    st.session_state["validated_kb_entry"] = candidate
                else:
                    st.error("❌ **Validation Failed:**")
                    for err in val_resp.get("errors", [str(val_resp)]):
                        st.markdown(f"- `{err}`")

            # Publication Action
            if "validated_kb_entry" in st.session_state:
                st.markdown("---")
                st.info(f"Ready to publish verified explanation for **{st.session_state['validated_kb_entry']['permission']}**.")
                if st.button("🚀 Publish to Curated Knowledge Base", type="primary"):
                    ok_pub, pub_resp = api_client.publish_kb_entry(st.session_state["validated_kb_entry"], token)
                    if ok_pub:
                        st.success(f"🎉 Successfully published '{pub_resp.get('permission')}'! Knowledge base version upgraded to v{pub_resp.get('kb_version')}.")
                        del st.session_state["validated_kb_entry"]
                        st.rerun()
                    else:
                        st.error(f"Publication failed: {pub_resp}")

    # =========================================================================
    # TAB 5: SECURITY AUDIT TRAIL
    # =========================================================================
    with admin_tabs[4]:
        st.subheader("Security Event & Audit Trail Review")
        st.caption("Immutable forensic activity records capturing administrative actions, authentication flows, and security modifications.")

        log_col1, log_col2 = st.columns([2, 1])
        with log_col1:
            action_search = st.text_input("🔍 Filter by Action Type:", placeholder="e.g. ADMIN_UPDATE_USER, LOGIN_SUCCESS, PURPOSE_COMPARISON...", key="log_action_search")
        with log_col2:
            log_page = st.number_input("Audit Page:", min_value=1, value=1, step=1, key="admin_log_page")

        success_l, logs_resp = api_client.get_admin_audit_logs(
            token=token,
            page=log_page,
            page_size=20,
            action=action_search if action_search.strip() else None
        )

        if success_l and isinstance(logs_resp, dict):
            logs = logs_resp.get("items", [])
            total_logs = logs_resp.get("total", 0)
            total_log_pages = logs_resp.get("total_pages", 1)

            st.caption(f"Showing page {log_page} of {total_log_pages} ({total_logs} total recorded security events)")

            if logs:
                df_logs = pd.DataFrame(logs)
                df_logs.rename(columns={
                    "id": "Log ID",
                    "action": "Security Action",
                    "username": "User / Initiator",
                    "resource_type": "Resource",
                    "resource_id": "Target ID",
                    "ip_address": "IP Address",
                    "created_at": "Timestamp"
                }, inplace=True)

                st.dataframe(df_logs, use_container_width=True, hide_index=True)
            else:
                st.info("No audit log records match the search filter.")
        else:
            st.error(f"Failed to load audit logs: {logs_resp}")
