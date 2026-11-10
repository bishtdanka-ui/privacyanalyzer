"""
Privacy Policy Analyzer Service Shim
Re-exports the core 14-domain PolicyAnalyzer from backend.policy_analyzer
for backward compatibility across existing services and tests.
"""

from backend.policy_analyzer import (
    PolicyAnalyzer,
    PolicyAnalyzer as PrivacyPolicyAnalyzer,
    PolicyAnalysisError,
    PRIVACY_DOMAINS
)

__all__ = [
    "PolicyAnalyzer",
    "PrivacyPolicyAnalyzer",
    "PolicyAnalysisError",
    "PRIVACY_DOMAINS"
]
