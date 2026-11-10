"""
Explainability Service for Application Privacy and Permission Risk
Problem Statement: PS02 - Explainable Cybersecurity Application Privacy & Permission Analyzer

Objectives:
- Orchestrate permission classification, privacy impact, purpose comparison, and policy comparison.
- Generate unified, evidence-based explainability records matching exact requested schema:
  {
    "permission": "android.permission.CAMERA",
    "risk_level": "HIGH",
    "finding_category": "REQUIRES_REVIEW",
    "reason": "The application declares camera access.",
    "privacy_implication": "Camera access may expose images or video.",
    "purpose_comparison": "The supplied application purpose does not clearly explain camera functionality.",
    "review_question": "Why does this application require camera access?",
    "evidence_source": "AndroidManifest.xml",
    "source_reference": "/manifest/uses-permission[1]",
    "confidence": "RULE_BASED"
  }
- Save findings in `comparison_findings` and `permissions` database tables.
"""

from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from backend.risk_analyzer import PermissionRiskAnalyzer
from backend.comparison_service import ComparisonService
from backend.policy_analyzer import PolicyAnalyzer
from backend.models.comparison_finding import ComparisonFinding
from backend.models.permission import Permission


class ExplainabilityService:
    """
    Unified Explainable Analysis Orchestrator.
    Generates evidence-grounded findings without falsely labeling applications as malicious.
    """

    @classmethod
    def analyze_permission(
        cls,
        perm_identifier: str,
        app_name: Optional[str] = None,
        app_purpose: Optional[str] = None,
        policy_findings: Optional[Dict[str, Any]] = None,
        source_reference: Optional[str] = None,
        evidence_source: str = "AndroidManifest.xml"
    ) -> Dict[str, Any]:
        """
        Produces a comprehensive, explainable finding record for a single permission.
        """
        # 1. Classification & Knowledge Base Lookup
        classification = PermissionRiskAnalyzer.classify_permission(perm_identifier)
        canonical = classification["permission"]
        prot_level = classification["protection_level"]
        sensitivity = classification["sensitivity_tier"]
        is_known = classification["is_known"]
        kb_entry = classification["kb_entry"]

        # 2. Privacy Impact
        privacy_impact = PermissionRiskAnalyzer.analyze_privacy_impact(canonical, kb_entry)

        # 3. Purpose Comparison
        purpose_comp = ComparisonService.compare_permission_with_purpose(
            perm_canonical=canonical,
            prot_level=prot_level,
            sensitivity_tier=sensitivity,
            app_name=app_name,
            app_purpose=app_purpose,
            is_known=is_known
        )
        finding_category = purpose_comp["finding_category"]

        # 4. Policy Comparison
        policy_comp = ComparisonService.compare_permission_with_policy(canonical, policy_findings)

        # 5. Risk Level Calculation
        risk_level = PermissionRiskAnalyzer.compute_risk_level(
            protection_level=prot_level,
            sensitivity_tier=sensitivity,
            purpose_alignment=finding_category,
            is_known=is_known
        )

        # Build Reason
        display_name = classification["display_name"]
        reason = f"The application declares {display_name.lower()} access in its manifest."

        # Build Privacy Implication
        sens_data = privacy_impact.get("information_accessed", "")
        if is_known:
            privacy_implication = f"{display_name} access may expose {sens_data.lower()}."
        else:
            privacy_implication = "Uncataloged capability with unspecified OS data exposure boundaries."

        # Derive source reference if not supplied
        src_ref = source_reference or f"/manifest/uses-permission[{canonical}]"

        return {
            "permission": canonical,
            "risk_level": risk_level,
            "finding_category": finding_category,
            "reason": reason,
            "privacy_implication": privacy_implication,
            "purpose_comparison": purpose_comp["purpose_comparison"],
            "review_question": purpose_comp.get("review_question") or f"Is {display_name} strictly necessary for the application workflow?",
            "evidence_source": evidence_source,
            "source_reference": src_ref,
            "confidence": "RULE_BASED",
            # Additional detailed explainability telemetry
            "protection_level": prot_level,
            "sensitivity_tier": sensitivity,
            "policy_status": policy_comp["policy_status"],
            "policy_explanation": policy_comp["policy_explanation"],
            "declaration_boundaries": privacy_impact["declaration_boundaries"]
        }

    @classmethod
    def evaluate_manifest_permissions(
        cls,
        permissions: List[Any],
        app_name: Optional[str] = None,
        app_purpose: Optional[str] = None,
        privacy_policy_text: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Evaluates a list of permissions (either raw string identifiers or structured dicts)
        against the application purpose and optional privacy policy.
        """
        # Run policy analysis if provided
        policy_findings = None
        if privacy_policy_text and privacy_policy_text.strip():
            policy_findings = PolicyAnalyzer.analyze_policy(privacy_policy_text, app_name=app_name)

        findings: List[Dict[str, Any]] = []
        risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0}
        category_counts = {
            "POTENTIALLY_EXPECTED": 0,
            "REQUIRES_REVIEW": 0,
            "PURPOSE_MISMATCH": 0,
            "UNKNOWN_PERMISSION": 0,
            "INSUFFICIENT_INFORMATION": 0
        }

        for idx, item in enumerate(permissions):
            if isinstance(item, dict):
                perm_name = item.get("permission_name") or item.get("name")
                src_ref = item.get("source_reference") or f"/manifest/uses-permission[{idx + 1}]"
                src_file = item.get("source_file") or "AndroidManifest.xml"
            else:
                perm_name = str(item)
                src_ref = f"/manifest/uses-permission[{idx + 1}]"
                src_file = "AndroidManifest.xml"

            if not perm_name or not perm_name.strip():
                continue

            finding = cls.analyze_permission(
                perm_identifier=perm_name,
                app_name=app_name,
                app_purpose=app_purpose,
                policy_findings=policy_findings,
                source_reference=src_ref,
                evidence_source=src_file
            )

            findings.append(finding)
            risk_counts[finding["risk_level"]] = risk_counts.get(finding["risk_level"], 0) + 1
            cat = finding["finding_category"]
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # Determine overall assessment level
        if risk_counts["HIGH"] >= 3 or category_counts["PURPOSE_MISMATCH"] >= 2:
            overall_risk = "HIGH"
        elif risk_counts["HIGH"] > 0 or risk_counts["MEDIUM"] >= 2 or category_counts["REQUIRES_REVIEW"] > 0:
            overall_risk = "MEDIUM"
        elif risk_counts["UNKNOWN"] > 0 and risk_counts["LOW"] == 0:
            overall_risk = "UNKNOWN"
        else:
            overall_risk = "LOW"

        return {
            "app_name": app_name or "Application Under Audit",
            "app_purpose": app_purpose or "Not specified",
            "total_permissions": len(findings),
            "overall_risk_level": overall_risk,
            "risk_counts": risk_counts,
            "category_counts": category_counts,
            "policy_provided": policy_findings is not None and policy_findings.get("provided", False),
            "findings": findings
        }

    @classmethod
    def save_findings_to_db(
        cls,
        db: Session,
        analysis_id: int,
        findings: List[Dict[str, Any]]
    ):
        """
        Persists explainability findings into `comparison_findings` and updates
        `permissions` table records for the specified analysis_id.
        """
        for f in findings:
            perm_canonical = f["permission"]
            
            # 1. Insert into comparison_findings table
            cf = ComparisonFinding(
                analysis_id=analysis_id,
                finding_type="PURPOSE_COMPARISON",
                severity=f["risk_level"],
                title=f"Purpose Assessment: {perm_canonical.split('.')[-1]} ({f['finding_category']})",
                explanation=f["purpose_comparison"],
                remediation=f["review_question"],
                risk_penalty=10.0 if f["risk_level"] == "HIGH" else (5.0 if f["risk_level"] == "MEDIUM" else 0.0),
                matched_data=f,
                permission=perm_canonical,
                finding_category=f["finding_category"],
                review_question=f["review_question"],
                purpose_comparison=f["purpose_comparison"],
                evidence_source=f["evidence_source"],
                source_reference=f["source_reference"],
                confidence=f["confidence"]
            )
            db.add(cf)

            # 2. Update existing permission record in permissions table if exists
            perm_record = db.query(Permission).filter(
                Permission.analysis_id == analysis_id,
                Permission.name == perm_canonical
            ).first()

            if perm_record:
                perm_record.finding_category = f["finding_category"]
                perm_record.purpose_alignment = f["purpose_comparison"]
                perm_record.risk_level = f["risk_level"]
                perm_record.review_question = f["review_question"]
                if f.get("source_reference"):
                    perm_record.source_reference = f["source_reference"]

        db.commit()

