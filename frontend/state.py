import streamlit as st
from typing import Optional, Dict, Any

def init_session_state():
    if "token" not in st.session_state:
        st.session_state["token"] = None
    if "user" not in st.session_state:
        st.session_state["user"] = None
    if "current_page" not in st.session_state:
        st.session_state["current_page"] = "Dashboard"
    if "active_analysis" not in st.session_state:
        st.session_state["active_analysis"] = None
    if "notification" not in st.session_state:
        st.session_state["notification"] = None

def is_authenticated() -> bool:
    return st.session_state.get("token") is not None and st.session_state.get("user") is not None

def is_admin() -> bool:
    user = st.session_state.get("user")
    return bool(user and user.get("role") == "admin")

def login_user(token: str, user_dict: Dict[str, Any]):
    st.session_state["token"] = token
    st.session_state["user"] = user_dict
    st.session_state["current_page"] = "Dashboard"

def logout_user():
    st.session_state["token"] = None
    st.session_state["user"] = None
    st.session_state["active_analysis"] = None
    st.session_state["current_page"] = "Dashboard"
    st.rerun()

def set_page(page_name: str):
    st.session_state["current_page"] = page_name
    st.rerun()

