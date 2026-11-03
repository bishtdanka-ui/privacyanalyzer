from typing import Dict, Any, List, Optional
from backend.services.permission_kb import permission_kb
from backend.services.privacy_policy_analyzer import PrivacyPolicyAnalyzer
from backend.services.purpose_matcher import PurposePermissionMatcher, GROUP_TO_DOMAIN_MAP

class ExplanationEngine:
    @classmethod
    def analyze(
        cls,
        parsed_manifest: Dict[str, Any],
        privacy_policy_text: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run full explainable risk and privacy analysis on parsed manifest data.
        """
        raw_perms: List[str] = parsed_manifest.get("permissions", [])
        
        # 1. Analyze Privacy Policy if present
        policy_analysis = PrivacyPolicyAnalyzer.analyze_policy_text(privacy_policy_text or "")
        
        # 2. Match permissions against policy for discrepancies
        discrepancies = PurposePermissionMatcher.match_permissions_with_policy(
            raw_perms,
            policy_analysis
        )

        # 3. Classify individual permissions
        classified_permissions = []
        dangerous_count = 0
        normal_count = 0
        special_count = 0
        base_severity_sum = 0.0

        disclosed_domains = policy_analysis.get("disclosed_domains", {})

        for p_name in raw_perms:
            meta = permission_kb.get_permission(p_name)
            prot = meta.get("protection_level", "normal")
            group = meta.get("group", "")
            domain = GROUP_TO_DOMAIN_MAP.get(group)

            is_disclosed = False
            if policy_analysis.get("provided") and domain and domain in disclosed_domains:
                is_disclosed = True

            # Determine discrepancy status for this specific permission
            disc_status = "NORMAL"
            matching_disc = [d for d in discrepancies if d["permission_name"] == p_name]
            if matching_disc:
                disc_status = matching_disc[0]["issue_type"]

            if prot in ("dangerous",):
                dangerous_count += 1
                base_severity_sum += meta.get("severity_score", 5.0)
            elif prot in ("special", "signature/special"):
                special_count += 1
                base_severity_sum += meta.get("severity_score", 6.0)
            else:
                normal_count += 1

            classified_permissions.append({
                "name": p_name,
                "short_name": meta.get("short_name", p_name.split(".")[-1]),
                "group": group,
                "protection_level": prot,
                "description": meta.get("description", ""),
                "privacy_risk": meta.get("privacy_risk", ""),
                "abuse_scenarios": meta.get("abuse_scenarios", []),
                "severity_score": meta.get("severity_score", 1.0),
                "remediation": meta.get("remediation", ""),
                "policy_disclosed": is_disclosed,
                "discrepancy_status": disc_status
            })

        # Sort permissions by severity score descending
        classified_permissions.sort(key=lambda x: x["severity_score"], reverse=True)

        # 4. Detect multi-permission dangerous combinations
        perm_set = set(raw_perms)
        combo_rules = permission_kb.get_combo_rules()
        combo_findings = []
        combo_penalty_total = 0.0

        for rule in combo_rules:
            req = rule.get("required_permissions", [])
            if all(r in perm_set for r in req):
                penalty = rule.get("risk_penalty", 10.0)
                combo_penalty_total += penalty
                combo_findings.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "risk_penalty": penalty,
                    "explanation": rule["explanation"],
                    "matched_permissions": req
                })

        # 5. Exported component attack surface penalty
        exported_count = parsed_manifest.get("exported_count", 0)
        component_penalty = min(exported_count * 3.0, 15.0)

        # 6. Target SDK penalty
        sdk_warnings = parsed_manifest.get("sdk_warnings", [])
        sdk_penalty = 0.0
        target_sdk = parsed_manifest.get("target_sdk")
        try:
            target_int = int(target_sdk) if target_sdk else 30
            if target_int < 23:
                sdk_penalty = 20.0
            elif target_int < 28:
                sdk_penalty = 12.0
            elif target_int < 31:
                sdk_penalty = 6.0
        except ValueError:
            pass

        # 7. Policy Discrepancy Penalty
        policy_penalty = 0.0
        for d in discrepancies:
            if d["severity"] == "CRITICAL":
                policy_penalty += 15.0
            elif d["severity"] == "HIGH":
                policy_penalty += 8.0
            elif d["severity"] == "MEDIUM":
                policy_penalty += 4.0
        policy_penalty = min(policy_penalty, 25.0)

        # 8. Compute Total Risk Score (0 - 100)
        # Base score normalized from severity sum (capped at 40 points)
        base_score = min((base_severity_sum / 2.0), 40.0)
        raw_total = base_score + min(combo_penalty_total, 30.0) + component_penalty + sdk_penalty + policy_penalty
        risk_score = round(min(max(raw_total, 5.0 if dangerous_count > 0 else 2.0), 100.0), 1)

        # 9. Classify Risk Level
        if risk_score >= 75.0:
            risk_level = "CRITICAL"
        elif risk_score >= 55.0:
            risk_level = "HIGH"
        elif risk_score >= 30.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "app_name": parsed_manifest.get("app_name", "Unknown App"),
            "package_name": parsed_manifest.get("package_name", "unknown.package"),
            "version_code": str(parsed_manifest.get("version_code", "1")),
            "version_name": str(parsed_manifest.get("version_name", "1.0.0")),
            "min_sdk": str(parsed_manifest.get("min_sdk", "N/A")),
            "target_sdk": str(parsed_manifest.get("target_sdk", "N/A")),
            "total_permissions": len(raw_perms),
            "dangerous_count": dangerous_count,
            "normal_count": normal_count,
            "special_count": special_count,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "exported_components_count": exported_count,
            "target_sdk_warnings": sdk_warnings,
            "permissions": classified_permissions,
            "combo_findings": combo_findings,
            "discrepancies": discrepancies,
            "policy_analysis": policy_analysis
        }

