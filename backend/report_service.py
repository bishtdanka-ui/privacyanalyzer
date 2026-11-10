"""
Report Generation Service for Explainable Application Privacy and Permission Analyzer
Problem Statement: PS02 - Explainable Cybersecurity Application Privacy & Permission Analyzer

Supports:
1. PDF (ReportLab - Stylized Cover Page + 6 Evidence-Linked Sections)
2. JSON (Complete structured findings with source references, analysis metadata, and limitations)
3. CSV (Well-structured tabular export for permissions, policy excerpts, purpose comparisons, and metrics)

Security:
- Strict ownership verification (owner or admin).
- Path traversal prevention.
- Safe generated filenames.
- Complete omission of sensitive authentication data, tokens, and server internal paths.
"""

import os
import io
import csv
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.graphics.shapes import Drawing, Polygon, Rect, Circle, String, Group
from reportlab.pdfgen import canvas
from fastapi import HTTPException, status
from sqlalchemy.orm import Session, joinedload

from backend.config import settings
from backend.models.user import User
from backend.models.analysis import Analysis
from backend.models.permission import Permission
from backend.models.policy_excerpt import PolicyExcerpt
from backend.models.comparison_finding import ComparisonFinding
from backend.models.report import Report
from backend.explainability_service import ExplainabilityService
from backend.risk_analyzer import PermissionRiskAnalyzer


# Color Palette
COLOR_NAVY_DARK = colors.HexColor("#0B132B")
COLOR_NAVY_MID = colors.HexColor("#1C2541")
COLOR_CYAN_ACCENT = colors.HexColor("#00D4FF")
COLOR_BLUE_PRIMARY = colors.HexColor("#1E3A8A")
COLOR_TEXT_PRIMARY = colors.HexColor("#1E293B")
COLOR_TEXT_MUTED = colors.HexColor("#64748B")
COLOR_BORDER = colors.HexColor("#E2E8F0")
COLOR_BG_LIGHT = colors.HexColor("#F8FAFC")

RISK_HEX = {
    "LOW": "#15803D",        # Emerald green
    "MEDIUM": "#D97706",     # Warm amber
    "HIGH": "#DC2626",       # Crimson red
    "CRITICAL": "#7F1D1D",   # Dark burgundy
    "UNKNOWN": "#6B7280",    # Slate grey
    "CONTEXT_DEPENDENT": "#D97706"  # Amber
}

RISK_BG_HEX = {
    "LOW": "#DCFCE7",
    "MEDIUM": "#FEF3C7",
    "HIGH": "#FEE2E2",
    "CRITICAL": "#FFE4E6",
    "UNKNOWN": "#F3F4F6",
    "CONTEXT_DEPENDENT": "#FEF3C7"
}


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and stamp total page count ('Page X of Y')
    and professional confidentiality footer across all report pages, suppressing on cover.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        if self._pageNumber == 1:
            return  # Suppress running headers and footers on the cover page

        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(COLOR_TEXT_MUTED)

        # Running Header
        self.drawString(36, 762, "PrivacyGuard | Evidence-Linked Application Privacy Audit Report")
        self.setStrokeColor(COLOR_BORDER)
        self.setLineWidth(0.5)
        self.line(36, 756, 576, 756)

        # Running Footer
        self.line(36, 32, 576, 32)
        self.drawString(36, 20, "Confidential - Cybersecurity Application Privacy Assessment (PS02)")
        self.drawRightString(576, 20, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


class ReportService:
    """
    Core reporting service managing data compilation and export generation for PDF, JSON, and CSV.
    """

    @classmethod
    def validate_ownership_and_get_analysis(
        cls,
        analysis_id: int,
        user: User,
        db: Session
    ) -> Analysis:
        """
        Verify that the requesting user owns the analysis or possesses admin privileges.
        Eager-loads related permissions, policy excerpts, and comparison findings.
        """
        analysis = db.query(Analysis).options(
            joinedload(Analysis.permissions),
            joinedload(Analysis.policy_excerpts),
            joinedload(Analysis.comparison_findings),
            joinedload(Analysis.reports)
        ).filter(Analysis.id == analysis_id).first()

        if not analysis:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis record #{analysis_id} not found."
            )

        if analysis.user_id != user.id and user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. You do not have permission to access this analysis report."
            )

        return analysis

    @classmethod
    def get_safe_filename(cls, app_name: str, analysis_id: int, extension: str) -> str:
        """
        Generates a clean, sanitized filename safe from path traversal attacks.
        """
        clean_app = "".join(c for c in app_name if c.isalnum() or c in ("_", "-")).strip()
        if not clean_app:
            clean_app = "Application"
        ext = extension.lstrip(".").lower()
        return f"PrivacyGuard_Audit_{clean_app}_{analysis_id}.{ext}"

    @classmethod
    def compile_report_data(cls, analysis: Analysis, db: Optional[Session] = None) -> Dict[str, Any]:
        """
        Compiles and standardizes all database findings, permissions, excerpts, and purpose comparisons
        into a comprehensive dictionary for PDF, JSON, and CSV rendering.
        """
        created_at_dt = analysis.created_at or datetime.now(timezone.utc)
        report_id = f"PG-AUDIT-{analysis.id:06d}-{created_at_dt.strftime('%Y%m%d')}"

        # 1. Permissions compilation
        permissions_list: List[Dict[str, Any]] = []
        unknown_permissions_list: List[Dict[str, Any]] = []

        risk_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        known_count = 0
        unknown_count = 0

        for p in analysis.permissions:
            prot_level = (p.protection_level or "normal").lower()
            is_unknown = prot_level == "unknown"

            if is_unknown:
                unknown_count += 1
            else:
                known_count += 1

            # Determine risk level
            risk_level = p.risk_level or ("HIGH" if prot_level in ("dangerous", "special") else "LOW")
            if is_unknown:
                risk_level = "UNKNOWN"

            risk_dist[risk_level] = risk_dist.get(risk_level, 0) + 1

            perm_entry = {
                "permission": p.name,
                "short_name": p.short_name or p.name.split(".")[-1],
                "category": p.permission_group or ("Custom / Vendor" if is_unknown else "General"),
                "protection_level": prot_level,
                "risk_level": risk_level,
                "description": p.description or ("Custom or third-party SDK permission declaration." if is_unknown else "Standard Android OS permission."),
                "privacy_implications": p.privacy_risk or ("May grant access to sensitive hardware or data interfaces when authorized." if prot_level == "dangerous" else "Standard device operation capability."),
                "source_reference": p.source_reference or "/manifest/uses-permission",
                "declaration_type": p.declaration_type or "uses-permission",
                "max_sdk_version": p.max_sdk_version,
                "is_duplicate": p.is_duplicate,
                "remediation": p.remediation or "Follow the principle of least privilege; request at runtime only when required."
            }
            permissions_list.append(perm_entry)

            if is_unknown:
                unknown_permissions_list.append({
                    "permission": p.name,
                    "source_reference": p.source_reference or "/manifest/uses-permission",
                    "reason_unsupported": "Declaration is not cataloged in standard Android Open Source Project (AOSP) permission specifications or curated knowledge base.",
                    "manual_verification_recommendation": "Inspect third-party vendor SDK specifications, native libraries, or decompiled DEX bytecode to verify function and intent."
                })

        # 2. Privacy Policy Excerpts compilation
        policy_excerpts_list: List[Dict[str, Any]] = []
        for pe in analysis.policy_excerpts:
            policy_excerpts_list.append({
                "domain": pe.domain,
                "excerpt_type": pe.excerpt_type,
                "stance": pe.sentiment_or_stance,
                "paragraph_reference": pe.paragraph_ref or "General Policy Text",
                "character_offsets": {
                    "start": pe.start_offset,
                    "end": pe.end_offset
                },
                "original_excerpt": pe.text_snippet,
                "summary": f"Stance: {pe.sentiment_or_stance.replace('_', ' ').capitalize()} for domain '{pe.domain}'"
            })

        # 3. Purpose Comparison compilation
        purpose_findings_list: List[Dict[str, Any]] = []
        supplied_purpose = "General Application Purpose (Default Evaluation)"

        purpose_cfs = [cf for cf in analysis.comparison_findings if cf.finding_type == "PURPOSE_COMPARISON"]
        if purpose_cfs:
            for cf in purpose_cfs:
                data = cf.matched_data if isinstance(cf.matched_data, dict) else {}
                if data.get("app_purpose") and supplied_purpose.startswith("General"):
                    supplied_purpose = data.get("app_purpose")

                purpose_findings_list.append({
                    "permission": cf.permission or data.get("permission", "unknown"),
                    "finding_category": cf.finding_category or data.get("finding_category", "REQUIRES_REVIEW"),
                    "severity": cf.severity or "MEDIUM",
                    "purpose_alignment": getattr(cf, "purpose_alignment", None) or ("POTENTIALLY_EXPECTED" if getattr(cf, "finding_category", None) == "POTENTIALLY_EXPECTED" else "UNEXPECTED"),
                    "why_expected_or_unexpected": cf.purpose_comparison or cf.explanation or data.get("purpose_comparison", "Evaluated based on standard Android capabilities."),
                    "review_questions": cf.review_question or cf.remediation or "Why is this capability requested by this application?",
                    "evidence_source": cf.evidence_source or "AndroidManifest.xml",
                    "source_reference": cf.source_reference or "/manifest/uses-permission"
                })
        else:
            # Dynamically generate findings if not pre-persisted
            eval_res = ExplainabilityService.evaluate_manifest_permissions(
                permissions=[p.name for p in analysis.permissions],
                app_name=analysis.app_name,
                app_purpose=None,
                privacy_policy_text=analysis.raw_policy
            )
            for f in eval_res.get("findings", []):
                purpose_findings_list.append({
                    "permission": f["permission"],
                    "finding_category": f["finding_category"],
                    "severity": f["risk_level"],
                    "purpose_alignment": "POTENTIALLY_EXPECTED" if f["finding_category"] == "POTENTIALLY_EXPECTED" else "UNEXPECTED",
                    "why_expected_or_unexpected": f["purpose_comparison"],
                    "review_questions": f["review_question"],
                    "evidence_source": f["evidence_source"],
                    "source_reference": f["source_reference"]
                })

        # 4. Multi-permission threat chains (combos)
        combo_cfs = [cf for cf in analysis.comparison_findings if cf.finding_type == "COMBO_THREAT"]
        combo_findings_list: List[Dict[str, Any]] = []
        for c in combo_cfs:
            data = c.matched_data if isinstance(c.matched_data, dict) else {}
            combo_findings_list.append({
                "combo_name": c.title,
                "severity": c.severity,
                "matched_permissions": data.get("matched_permissions", []),
                "explanation": c.explanation
            })

        # 5. Executive Summary synthesis
        total_p = len(permissions_list)
        dangerous_p = sum(1 for p in permissions_list if p["protection_level"] == "dangerous")
        special_p = sum(1 for p in permissions_list if p["protection_level"] == "special")
        normal_p = sum(1 for p in permissions_list if p["protection_level"] == "normal")

        # Observations synthesis
        observations = []
        if analysis.risk_level in ("CRITICAL", "HIGH"):
            observations.append(
                f"Application requests elevated privilege scope with {dangerous_p} dangerous permission(s) "
                f"and an overall risk index of {analysis.risk_score:.1f}/100."
            )
        else:
            observations.append(
                f"Application exhibits a restrained privilege footprint with {dangerous_p} dangerous permission(s) "
                f"and a low privacy risk profile ({analysis.risk_score:.1f}/100)."
            )

        if combo_findings_list:
            observations.append(
                f"{len(combo_findings_list)} multi-permission threat correlation chain(s) were identified (e.g., surveillance or exfiltration vectors)."
            )

        if unknown_count > 0:
            observations.append(
                f"{unknown_count} non-standard or proprietary vendor permission(s) detected requiring manual verification."
            )
        else:
            observations.append(
                "All declared permissions correspond directly to verified Android Open Source Project (AOSP) definitions."
            )

        if policy_excerpts_list:
            observations.append(
                f"Privacy policy analysis validated {len(policy_excerpts_list)} evidence-linked disclosure passage(s)."
            )
        else:
            observations.append(
                "No formal privacy policy was supplied for policy-to-manifest cross-examination."
            )

        observations_text = " ".join(observations)

        # 6. Technical Limitations
        limitations = [
            {
                "boundary": "RUNTIME_VERIFICATION",
                "statement": "Declared permissions define potential OS access capabilities when granted by the user, but do not prove runtime API execution, sensor activation, or background exfiltration."
            },
            {
                "boundary": "POLICY_VERIFICATION",
                "statement": "A privacy policy is a self-reported statement of intent by the application author, not technical verification of actual data handling, transmission, or backend storage practices."
            },
            {
                "boundary": "MALICE_DETERMINATION",
                "statement": "This analysis evaluates explainable privacy risk posture, surface area, and transparency; high risk indicators do not classify an application as malware or fraudulent."
            },
            {
                "boundary": "UNKNOWN_DECLARATIONS",
                "statement": "Unknown or custom vendor permissions cannot be statically verified without proprietary vendor documentation, decompiled bytecode (Smali/DEX), or dynamic runtime monitoring."
            }
        ]

        return {
            "report_metadata": {
                "report_id": report_id,
                "analysis_id": analysis.id,
                "application_name": analysis.app_name,
                "package_name": analysis.package_name,
                "version_name": analysis.version_name or "1.0",
                "version_code": analysis.version_code or "1",
                "min_sdk": analysis.min_sdk or "N/A",
                "target_sdk": analysis.target_sdk or "N/A",
                "exported_components_count": analysis.exported_components_count,
                "analysis_timestamp": created_at_dt.isoformat(),
                "report_generated_at": datetime.now(timezone.utc).isoformat(),
                "generator": "PrivacyGuard Explainable Security Engine (PS02)"
            },
            "executive_summary": {
                "total_permissions": total_p,
                "known_permissions": known_count,
                "unknown_permissions": unknown_count,
                "dangerous_count": dangerous_p,
                "normal_count": normal_p,
                "special_count": special_p,
                "risk_score": analysis.risk_score,
                "risk_level": analysis.risk_level,
                "risk_distribution": risk_dist,
                "overall_observations": observations_text
            },
            "extracted_permissions": permissions_list,
            "unknown_permissions": unknown_permissions_list,
            "privacy_policy_analysis": {
                "policy_provided": len(policy_excerpts_list) > 0 or bool(analysis.raw_policy),
                "excerpts": policy_excerpts_list
            },
            "purpose_comparison": {
                "supplied_purpose": supplied_purpose,
                "findings": purpose_findings_list
            },
            "multi_permission_threat_chains": combo_findings_list,
            "limitations": limitations
        }

    # =========================================================================
    # JSON REPORT GENERATION
    # =========================================================================
    @classmethod
    def generate_json_report(cls, analysis: Analysis, db: Optional[Session] = None) -> Dict[str, Any]:
        """
        Exports complete structured findings with source references and analysis metadata in JSON format.
        Ensures zero leakage of credentials, tokens, or internal filesystem paths.
        """
        return cls.compile_report_data(analysis, db)

    # =========================================================================
    # CSV REPORT GENERATION
    # =========================================================================
    @classmethod
    def generate_csv_report(
        cls,
        analysis: Analysis,
        section: Optional[str] = None,
        db: Optional[Session] = None
    ) -> str:
        """
        Creates well-structured CSV tables for permissions, policy findings, and purpose comparisons.
        If section is specified ('permissions', 'policy', 'purpose', 'unknown'), exports that single table.
        Otherwise, exports a comprehensive multi-section CSV report.
        """
        data = cls.compile_report_data(analysis, db)
        meta = data["report_metadata"]
        exec_sum = data["executive_summary"]
        perms = data["extracted_permissions"]
        unknowns = data["unknown_permissions"]
        policies = data["privacy_policy_analysis"]["excerpts"]
        purposes = data["purpose_comparison"]["findings"]
        limitations = data["limitations"]

        output = io.StringIO()
        writer = csv.writer(output)

        sec = (section or "all").lower()

        # SECTION: PERMISSIONS ONLY
        if sec in ("permissions", "permission"):
            writer.writerow([
                "Permission Identifier", "Short Name", "Category", "Protection Level",
                "Risk Level", "Source Reference", "Declaration Type", "Max SDK", "Is Duplicate",
                "Description", "Privacy Implications", "Remediation"
            ])
            for p in perms:
                writer.writerow([
                    p["permission"], p["short_name"], p["category"], p["protection_level"],
                    p["risk_level"], p["source_reference"], p["declaration_type"],
                    p["max_sdk_version"] or "None", p["is_duplicate"],
                    p["description"], p["privacy_implications"], p["remediation"]
                ])
            return output.getvalue()

        # SECTION: POLICY EXCERPTS ONLY
        if sec in ("policy", "privacy_policy", "policy_excerpts"):
            writer.writerow([
                "Topic / Domain", "Excerpt Type", "Stance / Summary", "Paragraph Reference",
                "Start Offset", "End Offset", "Original Policy Excerpt"
            ])
            for pe in policies:
                writer.writerow([
                    pe["domain"], pe["excerpt_type"], pe["stance"], pe["paragraph_reference"],
                    pe["character_offsets"]["start"], pe["character_offsets"]["end"],
                    pe["original_excerpt"]
                ])
            return output.getvalue()

        # SECTION: PURPOSE COMPARISON ONLY
        if sec in ("purpose", "purpose_comparison", "comparison"):
            writer.writerow([
                "Permission Examined", "Finding Category", "Severity", "Purpose Alignment",
                "Why Expected or Unexpected", "Review Questions", "Evidence Source", "Source Reference"
            ])
            for pf in purposes:
                writer.writerow([
                    pf["permission"], pf["finding_category"], pf["severity"], pf["purpose_alignment"],
                    pf["why_expected_or_unexpected"], pf["review_questions"],
                    pf["evidence_source"], pf["source_reference"]
                ])
            return output.getvalue()

        # SECTION: UNKNOWN PERMISSIONS ONLY
        if sec in ("unknown", "unknown_permissions"):
            writer.writerow([
                "Permission Identifier", "Source Reference", "Reason Unsupported", "Recommendation For Verification"
            ])
            for u in unknowns:
                writer.writerow([
                    u["permission"], u["source_reference"], u["reason_unsupported"],
                    u["manual_verification_recommendation"]
                ])
            return output.getvalue()

        # FULL COMPREHENSIVE MULTI-SECTION CSV
        writer.writerow(["# =============================================================================="])
        writer.writerow(["# PRIVACYGUARD EVIDENCE-LINKED CYBERSECURITY AUDIT REPORT"])
        writer.writerow([f"# Report ID: {meta['report_id']}"])
        writer.writerow([f"# Application: {meta['application_name']} ({meta['package_name']})"])
        writer.writerow([f"# Version: {meta['version_name']} (Code {meta['version_code']})"])
        writer.writerow([f"# Target SDK: {meta['target_sdk']} | Min SDK: {meta['min_sdk']}"])
        writer.writerow([f"# Analysis Date: {meta['analysis_timestamp']}"])
        writer.writerow([f"# Risk Assessment: {exec_sum['risk_level']} ({exec_sum['risk_score']:.1f}/100)"])
        writer.writerow(["# =============================================================================="])
        writer.writerow([])

        # Table 1: Executive Summary
        writer.writerow(["[SECTION 1: EXECUTIVE SUMMARY METRICS]"])
        writer.writerow(["Metric", "Value"])
        writer.writerow(["Total Permissions", exec_sum["total_permissions"]])
        writer.writerow(["Known Permissions", exec_sum["known_permissions"]])
        writer.writerow(["Unknown Permissions", exec_sum["unknown_permissions"]])
        writer.writerow(["Dangerous Permissions", exec_sum["dangerous_count"]])
        writer.writerow(["Normal Permissions", exec_sum["normal_count"]])
        writer.writerow(["Special Permissions", exec_sum["special_count"]])
        writer.writerow(["Overall Risk Score", f"{exec_sum['risk_score']:.1f}/100"])
        writer.writerow(["Overall Risk Level", exec_sum["risk_level"]])
        writer.writerow(["Observations", exec_sum["overall_observations"]])
        writer.writerow([])

        # Table 2: Extracted Permissions
        writer.writerow(["[SECTION 2: EXTRACTED PERMISSIONS]"])
        writer.writerow([
            "Permission Identifier", "Short Name", "Category", "Protection Level",
            "Risk Level", "Source Reference", "Description", "Privacy Implications", "Remediation"
        ])
        for p in perms:
            writer.writerow([
                p["permission"], p["short_name"], p["category"], p["protection_level"],
                p["risk_level"], p["source_reference"], p["description"],
                p["privacy_implications"], p["remediation"]
            ])
        writer.writerow([])

        # Table 3: Unknown Permissions
        writer.writerow(["[SECTION 3: UNKNOWN PERMISSIONS]"])
        writer.writerow([
            "Permission Identifier", "Source Reference", "Reason Unsupported", "Recommendation For Verification"
        ])
        if unknowns:
            for u in unknowns:
                writer.writerow([
                    u["permission"], u["source_reference"], u["reason_unsupported"],
                    u["manual_verification_recommendation"]
                ])
        else:
            writer.writerow(["NONE", "N/A", "All declared permissions conform to standard Android specifications.", "None required."])
        writer.writerow([])

        # Table 4: Privacy Policy Analysis
        writer.writerow(["[SECTION 4: PRIVACY POLICY EVIDENCE]"])
        writer.writerow([
            "Topic / Domain", "Excerpt Type", "Stance / Summary", "Paragraph Reference",
            "Start Offset", "End Offset", "Original Policy Excerpt"
        ])
        if policies:
            for pe in policies:
                writer.writerow([
                    pe["domain"], pe["excerpt_type"], pe["stance"], pe["paragraph_reference"],
                    pe["character_offsets"]["start"], pe["character_offsets"]["end"],
                    pe["original_excerpt"]
                ])
        else:
            writer.writerow(["No Policy Supplied", "N/A", "N/A", "N/A", "0", "0", "No formal privacy policy was provided for cross-examination."])
        writer.writerow([])

        # Table 5: Purpose Comparison
        writer.writerow(["[SECTION 5: APPLICATION PURPOSE COMPARISON]"])
        writer.writerow([f"# Supplied Application Purpose: {data['purpose_comparison']['supplied_purpose']}"])
        writer.writerow([
            "Permission Examined", "Finding Category", "Severity", "Purpose Alignment",
            "Why Expected or Unexpected", "Review Questions", "Evidence Source", "Source Reference"
        ])
        for pf in purposes:
            writer.writerow([
                pf["permission"], pf["finding_category"], pf["severity"], pf["purpose_alignment"],
                pf["why_expected_or_unexpected"], pf["review_questions"],
                pf["evidence_source"], pf["source_reference"]
            ])
        writer.writerow([])

        # Table 6: Limitations
        writer.writerow(["[SECTION 6: EXPLAINABILITY BOUNDARIES AND LIMITATIONS]"])
        writer.writerow(["Boundary Principle", "Declaration Statement"])
        for lim in limitations:
            writer.writerow([lim["boundary"], lim["statement"]])

        return output.getvalue()

    # =========================================================================
    # PDF REPORT GENERATION (Cover Page + 6 Evidence-Linked Sections)
    # =========================================================================
    @classmethod
    def generate_pdf_report(cls, analysis: Analysis, db: Optional[Session] = None) -> str:
        """
        Builds a publication-grade ReportLab PDF report containing:
        - Cover page (PrivacyGuard Shield Logo, App Name, Analysis Date, Report ID)
        - Section 1: Executive Summary (Metrics, Risk distribution, Observations)
        - Section 2: Extracted Permissions (Exact identifier, Category, Description, Impact, Level, Risk, Source)
        - Section 3: Unknown Permissions (Exact identifier, Source, Reason, Manual recommendation)
        - Section 4: Privacy Policy Analysis (Excerpts, Topics, Summaries, References)
        - Section 5: Application Purpose Comparison (User Purpose, Examined perms, Expected/Unexpected, Review questions)
        - Section 6: Limitations (4 clear boundary statements)
        Returns the absolute filepath to the generated PDF.
        """
        data = cls.compile_report_data(analysis, db)
        meta = data["report_metadata"]
        exec_sum = data["executive_summary"]
        perms = data["extracted_permissions"]
        unknowns = data["unknown_permissions"]
        policies = data["privacy_policy_analysis"]["excerpts"]
        purposes = data["purpose_comparison"]["findings"]
        combos = data["multi_permission_threat_chains"]
        limitations = data["limitations"]

        safe_name = cls.get_safe_filename(analysis.app_name, analysis.id, "pdf")
        unique_filename = f"report_{analysis.id}_{uuid.uuid4().hex[:10]}.pdf"
        filepath = settings.REPORT_OUTPUT_DIR / unique_filename

        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        # Typography Styles
        title_style = ParagraphStyle(
            "CoverTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=28,
            textColor=COLOR_NAVY_DARK,
            alignment=1,  # Center
            spaceAfter=8
        )

        subtitle_style = ParagraphStyle(
            "CoverSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=15,
            textColor=COLOR_TEXT_MUTED,
            alignment=1,
            spaceAfter=20
        )

        h1_style = ParagraphStyle(
            "SectionH1",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=COLOR_NAVY_MID,
            spaceBefore=14,
            spaceAfter=8
        )

        body_style = ParagraphStyle(
            "BodyDark",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11.5,
            textColor=COLOR_TEXT_PRIMARY
        )

        bold_style = ParagraphStyle(
            "BodyBold",
            parent=body_style,
            fontName="Helvetica-Bold"
        )

        code_style = ParagraphStyle(
            "CodeFont",
            parent=body_style,
            fontName="Courier",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0F172A")
        )

        callout_style = ParagraphStyle(
            "CalloutText",
            parent=body_style,
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#334155")
        )

        story: List[Any] = []

        # =====================================================================
        # COVER PAGE
        # =====================================================================
        story.append(Spacer(1, 40))

        # 1. PrivacyGuard Logo Drawing
        logo_drawing = Drawing(540, 100)
        # Shield background
        shield_bg = Polygon(
            points=[230, 95, 310, 95, 310, 50, 270, 15, 230, 50],
            fillColor=COLOR_NAVY_DARK,
            strokeColor=COLOR_CYAN_ACCENT,
            strokeWidth=3
        )
        logo_drawing.add(shield_bg)
        # Inner shield outline
        shield_inner = Polygon(
            points=[240, 87, 300, 87, 300, 53, 270, 25, 240, 53],
            fillColor=COLOR_NAVY_MID,
            strokeColor=colors.HexColor("#3B82F6"),
            strokeWidth=1
        )
        logo_drawing.add(shield_inner)
        # Shield PG Emblem
        emblem_text = String(
            270, 48, "PG",
            textAnchor="middle",
            fontSize=18,
            fontName="Helvetica-Bold",
            fillColor=COLOR_CYAN_ACCENT
        )
        logo_drawing.add(emblem_text)
        story.append(logo_drawing)

        story.append(Paragraph("PRIVACYGUARD", title_style))
        story.append(Paragraph("Explainable Cybersecurity Application Privacy & Permission Analyzer", subtitle_style))
        story.append(Spacer(1, 15))

        # Cover Metadata Card
        meta_table_data = [
            [
                Paragraph("<b>Application Name:</b>", body_style),
                Paragraph(f"<b>{meta['application_name']}</b>", bold_style)
            ],
            [
                Paragraph("<b>Package Identifier:</b>", body_style),
                Paragraph(f"<font name='Courier'>{meta['package_name']}</font>", code_style)
            ],
            [
                Paragraph("<b>Analysis Date:</b>", body_style),
                Paragraph(f"{meta['analysis_timestamp'][:10]} ({meta['analysis_timestamp'][11:19]} UTC)", body_style)
            ],
            [
                Paragraph("<b>Report Identifier:</b>", body_style),
                Paragraph(f"<b>{meta['report_id']}</b>", bold_style)
            ],
            [
                Paragraph("<b>Version / SDK:</b>", body_style),
                Paragraph(f"v{meta['version_name']} (code {meta['version_code']}) | Target SDK: {meta['target_sdk']} | Min SDK: {meta['min_sdk']}", body_style)
            ]
        ]

        meta_table = Table(meta_table_data, colWidths=[150, 310])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), COLOR_BG_LIGHT),
            ('BOX', (0, 0), (-1, -1), 1, COLOR_BORDER),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 14),
            ('RIGHTPADDING', (0, 0), (-1, -1), 14),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 25))

        # Overall Assessment Banner
        risk_lvl = exec_sum["risk_level"]
        risk_col = colors.HexColor(RISK_HEX.get(risk_lvl, "#64748B"))
        risk_bg = colors.HexColor(RISK_BG_HEX.get(risk_lvl, "#F1F5F9"))

        risk_banner_data = [[
            Paragraph(
                f"<font size='11'><b>OVERALL RISK ASSESSMENT RATING:</b></font><br/>"
                f"<font size='18' color='{RISK_HEX.get(risk_lvl, '#64748B')}'><b>{risk_lvl}</b></font> "
                f"<font size='12' color='#475569'>(Risk Score: {exec_sum['risk_score']:.1f}/100)</font><br/>"
                f"<font size='8' color='#64748B'>Evaluated according to Android OS protection boundaries and explainability standards.</font>",
                ParagraphStyle("RiskBanner", parent=body_style, alignment=1)
            )
        ]]
        risk_banner = Table(risk_banner_data, colWidths=[460])
        risk_banner.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), risk_bg),
            ('BOX', (0, 0), (-1, -1), 1.5, risk_col),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ]))
        story.append(risk_banner)

        story.append(Spacer(1, 40))
        story.append(Paragraph(
            "Evidence-Linked Forensic Security Assessment | Problem Statement: PS02 | Antigravity AI Cybersecurity",
            ParagraphStyle("CoverFooter", parent=subtitle_style, fontSize=8, textColor=COLOR_TEXT_MUTED)
        ))

        # End of Cover Page
        story.append(PageBreak())

        # =====================================================================
        # SECTION 1: EXECUTIVE SUMMARY
        # =====================================================================
        story.append(Paragraph("1. Executive Summary", h1_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=COLOR_BLUE_PRIMARY, spaceAfter=8))

        # Metrics KPI Grid
        kpi_data = [
            [
                Paragraph("<b>Total Permissions</b>", bold_style),
                Paragraph(str(exec_sum["total_permissions"]), bold_style),
                Paragraph("<b>Known Permissions</b>", bold_style),
                Paragraph(str(exec_sum["known_permissions"]), bold_style)
            ],
            [
                Paragraph("<b>Unknown Permissions</b>", bold_style),
                Paragraph(f"<font color='{'#DC2626' if exec_sum['unknown_permissions'] > 0 else '#15803D'}'><b>{exec_sum['unknown_permissions']}</b></font>", bold_style),
                Paragraph("<b>Dangerous Perms</b>", bold_style),
                Paragraph(f"<font color='{'#DC2626' if exec_sum['dangerous_count'] > 0 else '#475569'}'><b>{exec_sum['dangerous_count']}</b></font>", bold_style)
            ],
            [
                Paragraph("<b>Normal Perms</b>", bold_style),
                Paragraph(str(exec_sum["normal_count"]), body_style),
                Paragraph("<b>Special Perms</b>", bold_style),
                Paragraph(str(exec_sum["special_count"]), body_style)
            ]
        ]
        kpi_table = Table(kpi_data, colWidths=[135, 135, 135, 135])
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), COLOR_BG_LIGHT),
            ('BOX', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(kpi_table)
        story.append(Spacer(1, 10))

        # Risk Distribution Table
        rd = exec_sum["risk_distribution"]
        risk_dist_data = [
            [
                Paragraph("<b>Critical Risk</b>", bold_style),
                Paragraph(f"<font color='#7F1D1D'><b>{rd.get('CRITICAL', 0)}</b></font>", bold_style),
                Paragraph("<b>High Risk</b>", bold_style),
                Paragraph(f"<font color='#DC2626'><b>{rd.get('HIGH', 0)}</b></font>", bold_style),
                Paragraph("<b>Medium Risk</b>", bold_style),
                Paragraph(f"<font color='#D97706'><b>{rd.get('MEDIUM', 0)}</b></font>", bold_style),
                Paragraph("<b>Low Risk</b>", bold_style),
                Paragraph(f"<font color='#15803D'><b>{rd.get('LOW', 0)}</b></font>", bold_style),
            ]
        ]
        risk_dist_table = Table(risk_dist_data, colWidths=[75, 60, 65, 60, 75, 60, 65, 60])
        risk_dist_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
            ('BOX', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
        ]))
        story.append(risk_dist_table)
        story.append(Spacer(1, 10))

        # Overall Observations Callout Box
        obs_box_data = [[
            Paragraph(
                f"<b>Overall Security Posture & Forensic Observations:</b><br/>{exec_sum['overall_observations']}",
                callout_style
            )
        ]]
        obs_table = Table(obs_box_data, colWidths=[540])
        obs_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#EFF6FF")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#93C5FD")),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(obs_table)

        # Multi-Permission Threat Chains if any
        if combos:
            story.append(Spacer(1, 8))
            story.append(Paragraph(f"<b>Multi-Permission Threat Chains Detected ({len(combos)}):</b>", bold_style))
            combo_rows = [[
                Paragraph("<b>Attack / Threat Vector</b>", bold_style),
                Paragraph("<b>Severity</b>", bold_style),
                Paragraph("<b>Correlated Permissions & Impact</b>", bold_style)
            ]]
            for c in combos:
                combo_rows.append([
                    Paragraph(f"<b>{c['combo_name']}</b>", body_style),
                    Paragraph(f"<font color='{RISK_HEX.get(c['severity'], '#DC2626')}'><b>{c['severity']}</b></font>", bold_style),
                    Paragraph(f"<b>Permissions:</b> {', '.join(c.get('matched_permissions', []))}<br/>{c['explanation']}", body_style)
                ])
            combo_tbl = Table(combo_rows, colWidths=[140, 60, 340])
            combo_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#FEE2E2")),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#FCA5A5")),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#FECACA")),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(combo_tbl)

        story.append(Spacer(1, 14))

        # =====================================================================
        # SECTION 2: EXTRACTED PERMISSIONS
        # =====================================================================
        story.append(Paragraph(f"2. Extracted Android Permissions ({len(perms)} Total)", h1_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=COLOR_BLUE_PRIMARY, spaceAfter=8))
        story.append(Paragraph(
            "Every permission extracted from the manifest with verified Android protection level, privacy impact, and declaration source location:",
            body_style
        ))
        story.append(Spacer(1, 6))

        perm_table_rows = [[
            Paragraph("<b>Permission Identifier & Category</b>", bold_style),
            Paragraph("<b>Level / Risk</b>", bold_style),
            Paragraph("<b>Source Reference</b>", bold_style),
            Paragraph("<b>Plain-Language Description & Potential Privacy Implications</b>", bold_style)
        ]]

        for p in perms:
            prot_color = RISK_HEX.get(p["risk_level"], "#475569")
            perm_table_rows.append([
                Paragraph(
                    f"<b>{p['short_name']}</b><br/>"
                    f"<font name='Courier' size='7'>{p['permission']}</font><br/>"
                    f"<font color='#64748B'>Category: {p['category']}</font>",
                    body_style
                ),
                Paragraph(
                    f"<b>{p['protection_level']}</b><br/>"
                    f"<font color='{prot_color}'><b>{p['risk_level']}</b></font>",
                    body_style
                ),
                Paragraph(
                    f"<font name='Courier' size='7'>{p['source_reference']}</font>",
                    body_style
                ),
                Paragraph(
                    f"<b>Description:</b> {p['description']}<br/>"
                    f"<b>Privacy Implication:</b> {p['privacy_implications']}",
                    body_style
                )
            ])

        perm_table = Table(perm_table_rows, colWidths=[140, 65, 95, 240])
        perm_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ('BOX', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(perm_table)
        story.append(Spacer(1, 14))

        # =====================================================================
        # SECTION 3: UNKNOWN PERMISSIONS
        # =====================================================================
        story.append(Paragraph(f"3. Unknown & Non-Standard Permissions ({len(unknowns)} Detected)", h1_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=COLOR_BLUE_PRIMARY, spaceAfter=8))

        if unknowns:
            story.append(Paragraph(
                "The following declarations are not cataloged in standard AOSP definitions and require manual verification:",
                body_style
            ))
            story.append(Spacer(1, 6))

            unk_rows = [[
                Paragraph("<b>Exact Identifier</b>", bold_style),
                Paragraph("<b>Source Reference</b>", bold_style),
                Paragraph("<b>Reason Unsupported</b>", bold_style),
                Paragraph("<b>Manual Verification Recommendation</b>", bold_style)
            ]]
            for u in unknowns:
                unk_rows.append([
                    Paragraph(f"<font name='Courier' size='7'><b>{u['permission']}</b></font>", code_style),
                    Paragraph(f"<font name='Courier' size='7'>{u['source_reference']}</font>", body_style),
                    Paragraph(u["reason_unsupported"], body_style),
                    Paragraph(f"<b>Recommendation:</b> {u['manual_verification_recommendation']}", body_style)
                ])
            unk_table = Table(unk_rows, colWidths=[130, 90, 150, 170])
            unk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#FEF3C7")),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#FDE68A")),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#FDE68A")),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(unk_table)
        else:
            good_box = [[
                Paragraph(
                    "<b>✓ Zero Unknown Permissions Detected:</b> All declared permissions correspond to recognized Android platform standard specifications. No proprietary OEM or undocumented declarations were encountered.",
                    callout_style
                )
            ]]
            good_table = Table(good_box, colWidths=[540])
            good_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#DCFCE7")),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#86EFAC")),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ]))
            story.append(good_table)

        story.append(Spacer(1, 14))

        # =====================================================================
        # SECTION 4: PRIVACY POLICY ANALYSIS
        # =====================================================================
        story.append(Paragraph(f"4. Privacy Policy Evidence & Disclosure Analysis ({len(policies)} Excerpts)", h1_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=COLOR_BLUE_PRIMARY, spaceAfter=8))

        if policies:
            story.append(Paragraph(
                "Evidence-linked policy findings grounded directly in user-supplied privacy policy text with paragraph and character offsets:",
                body_style
            ))
            story.append(Spacer(1, 6))

            pol_rows = [[
                Paragraph("<b>Domain & Stance</b>", bold_style),
                Paragraph("<b>Location / Reference</b>", bold_style),
                Paragraph("<b>Original Text Excerpt</b>", bold_style),
                Paragraph("<b>Explainable Finding</b>", bold_style)
            ]]

            for pe in policies:
                pol_rows.append([
                    Paragraph(
                        f"<b>{pe['domain']}</b><br/>"
                        f"<font color='#0D9488'><b>{pe['stance'].replace('_', ' ').capitalize()}</b></font>",
                        body_style
                    ),
                    Paragraph(
                        f"<b>{pe['paragraph_reference']}</b><br/>"
                        f"<font color='#64748B'>Chars: {pe['character_offsets']['start']}–{pe['character_offsets']['end']}</font>",
                        body_style
                    ),
                    Paragraph(
                        f"<i>\"{pe['original_excerpt']}\"</i>",
                        body_style
                    ),
                    Paragraph(pe["summary"], body_style)
                ])

            pol_table = Table(pol_rows, colWidths=[100, 90, 210, 140])
            pol_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ('BOX', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(pol_table)
        else:
            no_pol_box = [[
                Paragraph(
                    "<b>Notice — No Privacy Policy Supplied:</b> A formal privacy policy text was not supplied for this application audit. Absence of privacy policy text limits disclosure cross-examination; in accordance with explainable security principles, absence is not treated as evidence of malicious conduct.",
                    callout_style
                )
            ]]
            no_pol_tbl = Table(no_pol_box, colWidths=[540])
            no_pol_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ('BOX', (0, 0), (-1, -1), 1, COLOR_BORDER),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ]))
            story.append(no_pol_tbl)

        story.append(Spacer(1, 14))

        # =====================================================================
        # SECTION 5: APPLICATION PURPOSE COMPARISON
        # =====================================================================
        story.append(Paragraph("5. Application Purpose Comparison & Review Questions", h1_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=COLOR_BLUE_PRIMARY, spaceAfter=8))

        # Purpose Context Header
        story.append(Paragraph(
            f"<b>Stated Application Purpose:</b> <i>\"{data['purpose_comparison']['supplied_purpose']}\"</i>",
            bold_style
        ))
        story.append(Paragraph(
            "Comparing declared permissions against application purpose to evaluate whether access is potentially expected or requires developer review:",
            body_style
        ))
        story.append(Spacer(1, 6))

        if purposes:
            purp_rows = [[
                Paragraph("<b>Permission Examined</b>", bold_style),
                Paragraph("<b>Category & Severity</b>", bold_style),
                Paragraph("<b>Why Expected or Unexpected</b>", bold_style),
                Paragraph("<b>Forensic Review Questions</b>", bold_style)
            ]]

            for pf in purposes[:18]:  # prioritized top findings
                cat_color = "#DC2626" if pf["finding_category"] == "PURPOSE_MISMATCH" else ("#D97706" if pf["finding_category"] == "REQUIRES_REVIEW" else "#15803D")
                purp_rows.append([
                    Paragraph(f"<font name='Courier' size='7'><b>{pf['permission']}</b></font>", code_style),
                    Paragraph(
                        f"<font color='{cat_color}'><b>{pf['finding_category']}</b></font><br/>"
                        f"<font color='#64748B'>Severity: {pf['severity']}</font>",
                        body_style
                    ),
                    Paragraph(pf["why_expected_or_unexpected"], body_style),
                    Paragraph(f"<b>Review:</b> {pf['review_questions']}", body_style)
                ])

            purp_tbl = Table(purp_rows, colWidths=[120, 95, 175, 150])
            purp_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ('BOX', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(purp_tbl)

        story.append(Spacer(1, 14))

        # =====================================================================
        # SECTION 6: LIMITATIONS & FORENSIC BOUNDARIES
        # =====================================================================
        story.append(Paragraph("6. Explainability Boundaries & Technical Limitations", h1_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=COLOR_BLUE_PRIMARY, spaceAfter=8))
        story.append(Paragraph(
            "To uphold explainable cybersecurity principles and avoid misleading conclusions, this assessment adheres to the following explicit boundaries:",
            body_style
        ))
        story.append(Spacer(1, 6))

        lim_rows = [[
            Paragraph("<b>Boundary Principle</b>", bold_style),
            Paragraph("<b>Forensic Declaration Statement</b>", bold_style)
        ]]

        for lim in limitations:
            lim_rows.append([
                Paragraph(f"<b>{lim['boundary'].replace('_', ' ').capitalize()}</b>", bold_style),
                Paragraph(lim["statement"], body_style)
            ])

        lim_table = Table(lim_rows, colWidths=[140, 400])
        lim_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#FEF2F2")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#FCA5A5")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#FECACA")),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(lim_table)

        story.append(Spacer(1, 15))
        story.append(Paragraph(
            "<b>Certificate of Audit:</b> Produced automatically by PrivacyGuard Engine under strict static analysis constraints.",
            ParagraphStyle("CertNotice", parent=body_style, fontSize=7.5, textColor=COLOR_TEXT_MUTED, alignment=1)
        ))

        # Build document with running NumberedCanvas
        doc.build(story, canvasmaker=NumberedCanvas)
        return str(filepath)

