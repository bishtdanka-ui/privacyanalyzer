"""
PrivacyGuard — UI/UX Design System & Cyber Theme
Modern Cybersecurity SaaS Aesthetic: Dark Navy, Deep Blue, Electric Blue & Violet Accents.
"""

import streamlit as st

CYBER_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* Global Typography & Palette */
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    code, pre, .stCode, [data-testid="stCodeBlock"] {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Main Container Background */
    .stApp {
        background: radial-gradient(circle at 15% 15%, #0B132B 0%, #060913 100%) !important;
        color: #E2E8F0;
    }

    /* Header styling with Cyber Gradient */
    .cyber-title {
        background: linear-gradient(135deg, #00D4FF 0%, #7C3AED 50%, #A855F7 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800;
        letter-spacing: -0.5px;
        margin-bottom: 2px;
    }

    .cyber-subtitle {
        color: #94A3B8;
        font-size: 0.95rem;
        font-weight: 400;
        margin-bottom: 20px;
    }

    /* Professional Cyber Cards */
    .cyber-card {
        background: rgba(13, 21, 39, 0.7);
        border: 1px solid rgba(56, 189, 248, 0.18);
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
        backdrop-filter: blur(8px);
        margin-bottom: 16px;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }

    .cyber-card:hover {
        border-color: rgba(0, 212, 255, 0.4);
        transform: translateY(-1px);
    }

    /* Metric Cards */
    div[data-testid="stMetric"] {
        background: rgba(15, 23, 42, 0.8) !important;
        border: 1px solid rgba(56, 189, 248, 0.2) !important;
        border-radius: 10px !important;
        padding: 14px !important;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
    }

    div[data-testid="stMetricLabel"] {
        color: #94A3B8 !important;
        font-size: 0.85rem !important;
        font-weight: 500 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.5px !important;
    }

    div[data-testid="stMetricValue"] {
        color: #F8FAFC !important;
        font-weight: 700 !important;
    }

    /* Tabs Styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: transparent;
    }

    .stTabs [data-baseweb="tab"] {
        background-color: rgba(15, 23, 42, 0.6);
        border: 1px solid rgba(148, 163, 184, 0.15);
        border-radius: 8px;
        color: #94A3B8;
        padding: 8px 16px;
        font-weight: 500;
        transition: all 0.2s ease;
    }

    .stTabs [aria-selected="true"] {
        background-color: rgba(37, 99, 235, 0.25) !important;
        border-color: #00D4FF !important;
        color: #00D4FF !important;
        box-shadow: 0 0 12px rgba(0, 212, 255, 0.2);
    }

    /* Expanders */
    div[data-testid="stExpander"] {
        background: rgba(15, 23, 42, 0.5) !important;
        border: 1px solid rgba(56, 189, 248, 0.15) !important;
        border-radius: 8px !important;
        margin-bottom: 8px;
    }

    /* Buttons */
    .stButton>button {
        border-radius: 8px;
        font-weight: 600;
        transition: all 0.2s ease;
    }

    .stButton>button[kind="primary"] {
        background: linear-gradient(135deg, #0284C7 0%, #2563EB 50%, #7C3AED 100%);
        border: none;
        color: #FFFFFF;
        box-shadow: 0 4px 15px rgba(37, 99, 235, 0.35);
    }

    .stButton>button[kind="primary"]:hover {
        background: linear-gradient(135deg, #00D4FF 0%, #3B82F6 50%, #8B5CF6 100%);
        box-shadow: 0 6px 20px rgba(0, 212, 255, 0.45);
        transform: translateY(-1px);
    }

    /* Badges */
    .badge {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .badge-critical {
        background: rgba(239, 68, 68, 0.2);
        color: #F87171;
        border: 1px solid rgba(239, 68, 68, 0.4);
    }

    .badge-high {
        background: rgba(249, 115, 22, 0.2);
        color: #FB923C;
        border: 1px solid rgba(249, 115, 22, 0.4);
    }

    .badge-medium {
        background: rgba(234, 179, 8, 0.2);
        color: #FDE047;
        border: 1px solid rgba(234, 179, 8, 0.4);
    }

    .badge-low {
        background: rgba(16, 185, 129, 0.2);
        color: #34D399;
        border: 1px solid rgba(16, 185, 129, 0.4);
    }

    .badge-unknown {
        background: rgba(148, 163, 184, 0.2);
        color: #CBD5E1;
        border: 1px solid rgba(148, 163, 184, 0.4);
    }

    /* Data Tables */
    div[data-testid="stDataFrame"] {
        border: 1px solid rgba(56, 189, 248, 0.15) !important;
        border-radius: 8px !important;
        overflow: hidden;
    }
</style>
"""

def inject_cyber_theme():
    """Injects the cyber SaaS styling into the active Streamlit app session."""
    st.markdown(CYBER_CSS, unsafe_allow_html=True)

def render_brand_header(title: str, subtitle: str = ""):
    """Renders a consistent modern header with electric gradient accents."""
    st.markdown(f"<h1 class='cyber-title'>{title}</h1>", unsafe_allow_html=True)
    if subtitle:
        st.markdown(f"<p class='cyber-subtitle'>{subtitle}</p>", unsafe_allow_html=True)

def get_risk_badge_html(risk_level: str) -> str:
    """Returns HTML for an accessible, styled risk badge pill."""
    lvl = (risk_level or "LOW").upper()
    css_class = {
        "CRITICAL": "badge-critical",
        "HIGH": "badge-high",
        "MEDIUM": "badge-medium",
        "CONTEXT_DEPENDENT": "badge-medium",
        "LOW": "badge-low"
    }.get(lvl, "badge-unknown")
    icon = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "CONTEXT_DEPENDENT": "🟡",
        "LOW": "🟢"
    }.get(lvl, "⚪")
    display_title = "CONTEXT DEPENDENT" if lvl == "CONTEXT_DEPENDENT" else f"{lvl} RISK"
    return f"<span class='badge {css_class}'>{icon} {display_title}</span>"

