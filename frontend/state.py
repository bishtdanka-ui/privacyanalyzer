import streamlit as st
from typing import Optional, Dict, Any
from frontend.auth_client import auth_client

def init_session_state():
    if "token" not in st.session_state:
        st.session_state["token"] = None
    if "refresh_token" not in st.session_state:
        st.session_state["refresh_token"] = None
    if "user" not in st.session_state:
        st.session_state["user"] = None
    if "current_page" not in st.session_state:
        st.session_state["current_page"] = "Dashboard"
    if "auth_mode" not in st.session_state:
        st.session_state["auth_mode"] = "login"
    if "active_analysis" not in st.session_state:
        st.session_state["active_analysis"] = None
    if "notification" not in st.session_state:
        st.session_state["notification"] = None

def is_authenticated() -> bool:
    return auth_client.is_authenticated()

def is_admin() -> bool:
    return auth_client.is_admin()

def login_user(access_token: str, user_dict: Dict[str, Any], refresh_token: Optional[str] = None):
    st.session_state["token"] = access_token
    st.session_state["refresh_token"] = refresh_token
    st.session_state["user"] = user_dict
    st.session_state["current_page"] = "Dashboard"

def logout_user():
    auth_client.logout()
    st.rerun()

def set_page(page_name: str):
    st.session_state["current_page"] = page_name
    st.rerun()

