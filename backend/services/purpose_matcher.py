from typing import Dict, Any, List
from backend.services.permission_kb import permission_kb

GROUP_TO_DOMAIN_MAP = {
    "Camera": "Camera",
    "Microphone": "Microphone",
    "Location": "Location",
    "Contacts": "Contacts",
    "SMS": "SMS",
    "Storage": "Storage",
    "Phone": "Phone State",
    "Call Log": "Phone State",
    "Sensors": "Sensors"
}

class PurposePermissionMatcher:
    @classmethod
    def match_permissions_with_policy(
        cls,
        manifest_permissions: List[str],
        policy_analysis: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Compare requested permissions against privacy policy disclosures.
        Produces explainable discrepancy findings.
        """
        discrepancies = []
        is_policy_provided = policy_analysis.get("provided", False)

        disclosed_domains = policy_analysis.get("disclosed_domains", {})
        negated_domains = policy_analysis.get("negated_domains", {})

        for perm_name in manifest_permissions:
            meta = permission_kb.get_permission(perm_name)
            group = meta.get("group", "")
            prot_level = meta.get("protection_level", "normal")
            domain = GROUP_TO_DOMAIN_MAP.get(group)

            if not domain:
                continue

            # 1. Contradiction / Deceptive assertion:
            # Policy explicitly denies collecting this, yet app asks for it!
            if domain in negated_domains:
                negation_examples = " | ".join(negated_domains[domain][:2])
                discrepancies.append({
                    "permission_name": perm_name,
                    "issue_type": "DECEPTIVE_CONTRADICTION",
                    "severity": "CRITICAL",
                    "explanation": (
                        f"Direct contradiction detected: Privacy policy explicitly asserts '{negation_examples}', "
                        f"yet the application manifest actively requests permission '{perm_name}' ({group})."
                    ),
                    "remediation": f"Immediately remove {perm_name} or update the privacy policy to truthfully describe user-facing necessity."
                })
                continue

            # 2. Undisclosed Dangerous Permission:
            # If policy is provided, but this dangerous permission has no corresponding disclosure:
            if is_policy_provided and prot_level in ("dangerous", "special"):
                if domain not in disclosed_domains:
                    discrepancies.append({
                        "permission_name": perm_name,
                        "issue_type": "UNDISCLOSED_DANGEROUS_PERMISSION",
                        "severity": "HIGH",
                        "explanation": (
                            f"The application requests sensitive runtime permission '{perm_name}' ({group}), "
                            f"but the provided privacy policy never mentions collecting, processing, or securing {domain} data."
                        ),
                        "remediation": f"Draft an explicit disclosure clause in the privacy policy clarifying how {domain} data is processed."
                    })

        # 3. If policy was omitted completely, flag an advisory
        if not is_policy_provided:
            discrepancies.append({
                "permission_name": "GLOBAL_POLICY_OMISSION",
                "issue_type": "MISSING_PRIVACY_POLICY",
                "severity": "MEDIUM",
                "explanation": (
                    "No privacy policy text was provided for cross-verification. "
                    "Google Play and global privacy regulations (GDPR, CCPA) strictly mandate accessible privacy policies for apps requesting sensitive permissions."
                ),
                "remediation": "Provide a complete privacy policy URL and disclosure document prior to store distribution."
            })

        return discrepancies

