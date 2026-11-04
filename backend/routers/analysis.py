import os
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session, joinedload

from backend.database import get_db
from backend.models.user import User
from backend.models.analysis import Analysis
from backend.models.permission import Permission
from backend.models.policy_excerpt import PolicyExcerpt
from backend.models.comparison_finding import ComparisonFinding
from backend.models.report import Report
from backend.schemas.analysis import (
    ManifestTextAnalysisRequest,
    AnalysisResponse,
    AnalysisSummary,
    PermissionDetail,
    ComboFinding,
    PolicyDiscrepancy
)
from backend.security.dependencies import get_current_active_user
from backend.services.manifest_parser import ManifestParser, ManifestParseError
from backend.services.explanation_engine import ExplanationEngine
from backend.services.pdf_generator import PDFReportGenerator
from backend.services.audit_service import log_audit_event

router = APIRouter(prefix="/analysis", tags=["Analysis"])

def _process_and_save_analysis(
    manifest_xml: str,
    policy_text: Optional[str],
    user: User,
    request: Request,
    db: Session
) -> AnalysisResponse:
    # 1. Parse manifest safely
    try:
        parsed_manifest = ManifestParser.parse_xml_content(manifest_xml)
    except ManifestParseError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse XML: {str(e)}")

    # 2. Run explanation engine
    result = ExplanationEngine.analyze(parsed_manifest, policy_text)

    # 3. Save to analyses table
    analysis = Analysis(
        user_id=user.id,
        app_name=result["app_name"],
        package_name=result["package_name"],
        version_code=result.get("version_code"),
        version_name=result.get("version_name"),
        min_sdk=result.get("min_sdk"),
        target_sdk=result.get("target_sdk"),
        total_permissions=result["total_permissions"],
        dangerous_count=result["dangerous_count"],
        normal_count=result["normal_count"],
        special_count=result["special_count"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        exported_components_count=result["exported_components_count"],
        raw_manifest=manifest_xml,
        raw_policy=policy_text or None
    )
    db.add(analysis)
    db.flush()  # Generates analysis.id

    # 4. Save normalized permissions to permissions table
    for p in result.get("permissions", []):
        perm_record = Permission(
            analysis_id=analysis.id,
            name=p["name"],
            short_name=p["short_name"],
            permission_group=p.get("group"),
            protection_level=p.get("protection_level", "normal"),
            description=p.get("description"),
            privacy_risk=p.get("privacy_risk"),
            abuse_scenarios=p.get("abuse_scenarios"),
            severity_score=p.get("severity_score", 1.0),
            remediation=p.get("remediation"),
            policy_disclosed=p.get("policy_disclosed", False),
            discrepancy_status=p.get("discrepancy_status", "NORMAL")
        )
        db.add(perm_record)

    # 5. Save policy excerpts to policy_excerpts table
    policy_analysis = result.get("policy_analysis", {})
    if policy_analysis.get("provided"):
        for domain, snippets in policy_analysis.get("disclosed_domains", {}).items():
            for snippet in snippets:
                db.add(PolicyExcerpt(
                    analysis_id=analysis.id,
                    domain=domain,
                    excerpt_type="disclosure",
                    text_snippet=snippet,
                    sentiment_or_stance="affirmative_collection"
                ))
        for domain, snippets in policy_analysis.get("negated_domains", {}).items():
            for snippet in snippets:
                db.add(PolicyExcerpt(
                    analysis_id=analysis.id,
                    domain=domain,
                    excerpt_type="negation",
                    text_snippet=snippet,
                    sentiment_or_stance="assertive_denial"
                ))

    # 6. Save comparison findings to comparison_findings table
    for c in result.get("combo_findings", []):
        db.add(ComparisonFinding(
            analysis_id=analysis.id,
            finding_type="COMBO_THREAT",
            severity=c.get("severity", "HIGH"),
            title=c.get("name", "Dangerous Combination"),
            explanation=c.get("explanation", ""),
            risk_penalty=c.get("risk_penalty", 0.0),
            matched_data=c.get("matched_permissions")
        ))

    for d in result.get("discrepancies", []):
        db.add(ComparisonFinding(
            analysis_id=analysis.id,
            finding_type=d.get("issue_type", "POLICY_DISCREPANCY"),
            severity=d.get("severity", "MEDIUM"),
            title=f"Discrepancy: {d.get('permission_name')}",
            explanation=d.get("explanation", ""),
            remediation=d.get("remediation", ""),
            risk_penalty=10.0 if d.get("severity") == "CRITICAL" else 5.0,
            matched_data={"permission": d.get("permission_name")}
        ))

    for w in result.get("target_sdk_warnings", []):
        db.add(ComparisonFinding(
            analysis_id=analysis.id,
            finding_type="SDK_WARNING",
            severity="MEDIUM",
            title="Target SDK Configuration Advisory",
            explanation=w,
            remediation="Upgrade targetSdkVersion to the latest supported Android API release."
        ))

    # 7. Generate PDF report & save record to reports table
    pdf_path = PDFReportGenerator.generate_report(result)
    file_size = os.path.getsize(pdf_path) if os.path.exists(pdf_path) else 0

    report_record = Report(
        analysis_id=analysis.id,
        user_id=user.id,
        report_format="PDF",
        file_path=pdf_path,
        file_size=file_size,
        summary_json={
            "app_name": analysis.app_name,
            "package_name": analysis.package_name,
            "risk_score": analysis.risk_score,
            "risk_level": analysis.risk_level
        }
    )
    db.add(report_record)

    # Commit all normalized tables
    db.commit()
    db.refresh(analysis)

    result["id"] = analysis.id
    result["pdf_report_path"] = pdf_path
    result["created_at"] = analysis.created_at

    client_ip = request.client.host if request and request.client else "unknown"
    log_audit_event(
        db,
        action="RUN_ANALYSIS",
        user_id=user.id,
        resource_type="ANALYSIS",
        resource_id=str(analysis.id),
        ip_address=client_ip
    )

    return AnalysisResponse(**result)

@router.post("/analyze", response_model=AnalysisResponse)
def analyze_manifest_text(
    req: ManifestTextAnalysisRequest,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    return _process_and_save_analysis(
        manifest_xml=req.manifest_xml,
        policy_text=req.privacy_policy_text,
        user=current_user,
        request=request,
        db=db
    )

@router.post("/upload", response_model=AnalysisResponse)
async def upload_manifest_file(
    manifest_file: UploadFile = File(...),
    policy_text: Optional[str] = Form(None),
    policy_file: Optional[UploadFile] = File(None),
    request: Request = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    content = await manifest_file.read()
    try:
        manifest_xml = content.decode("utf-8")
    except UnicodeDecodeError:
        try:
            manifest_xml = content.decode("latin-1")
        except Exception:
            raise HTTPException(status_code=400, detail="Uploaded manifest file must be a readable XML file.")

    effective_policy = policy_text or ""
    if policy_file and not effective_policy:
        p_bytes = await policy_file.read()
        try:
            effective_policy = p_bytes.decode("utf-8")
        except UnicodeDecodeError:
            effective_policy = p_bytes.decode("latin-1", errors="ignore")

    return _process_and_save_analysis(
        manifest_xml=manifest_xml,
        policy_text=effective_policy,
        user=current_user,
        request=request,
        db=db
    )

@router.get("/history", response_model=List[AnalysisSummary])
def get_user_history(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    records = db.query(Analysis).filter(
        Analysis.user_id == current_user.id
    ).order_by(Analysis.created_at.desc()).all()
    return records

@router.get("/{analysis_id}", response_model=AnalysisResponse)
def get_analysis_details(
    analysis_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    analysis = db.query(Analysis).options(
        joinedload(Analysis.permissions),
        joinedload(Analysis.comparison_findings),
        joinedload(Analysis.policy_excerpts),
        joinedload(Analysis.reports)
    ).filter(
        Analysis.id == analysis_id,
        Analysis.user_id == current_user.id
    ).first()

    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    # Reconstruct PermissionDetails from permissions table
    reconstructed_perms = []
    for p in analysis.permissions:
        reconstructed_perms.append(PermissionDetail(
            name=p.name,
            short_name=p.short_name,
            group=p.permission_group or "Unknown",
            protection_level=p.protection_level,
            description=p.description or "",
            privacy_risk=p.privacy_risk or "",
            abuse_scenarios=p.abuse_scenarios or [],
            severity_score=p.severity_score,
            remediation=p.remediation or "",
            policy_disclosed=p.policy_disclosed,
            discrepancy_status=p.discrepancy_status
        ))

    # Reconstruct Combos and Discrepancies from comparison_findings table
    combos = []
    discrepancies = []
    sdk_warnings = []
    for f in analysis.comparison_findings:
        if f.finding_type == "COMBO_THREAT":
            combos.append(ComboFinding(
                id=f.title.lower().replace(" ", "_"),
                name=f.title,
                severity=f.severity,
                risk_penalty=f.risk_penalty,
                explanation=f.explanation,
                matched_permissions=f.matched_data if isinstance(f.matched_data, list) else []
            ))
        elif f.finding_type == "SDK_WARNING":
            sdk_warnings.append(f.explanation)
        else:
            perm_name = f.matched_data.get("permission", f.title) if isinstance(f.matched_data, dict) else f.title
            discrepancies.append(PolicyDiscrepancy(
                permission_name=perm_name,
                issue_type=f.finding_type,
                severity=f.severity,
                explanation=f.explanation,
                remediation=f.remediation or ""
            ))

    # Get PDF file path from reports table
    pdf_report_path = None
    if analysis.reports:
        pdf_report_path = analysis.reports[0].file_path

    return AnalysisResponse(
        id=analysis.id,
        app_name=analysis.app_name,
        package_name=analysis.package_name,
        version_code=analysis.version_code,
        version_name=analysis.version_name,
        min_sdk=analysis.min_sdk,
        target_sdk=analysis.target_sdk,
        total_permissions=analysis.total_permissions,
        dangerous_count=analysis.dangerous_count,
        normal_count=analysis.normal_count,
        special_count=analysis.special_count,
        risk_score=analysis.risk_score,
        risk_level=analysis.risk_level,
        exported_components_count=analysis.exported_components_count,
        target_sdk_warnings=sdk_warnings,
        permissions=reconstructed_perms,
        combo_findings=combos,
        discrepancies=discrepancies,
        pdf_report_path=pdf_report_path,
        created_at=analysis.created_at
    )

@router.get("/{analysis_id}/pdf")
def download_pdf_report(
    analysis_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    report = db.query(Report).filter(
        Report.analysis_id == analysis_id,
        Report.user_id == current_user.id
    ).first()

    if not report or not os.path.exists(report.file_path):
        # Regenerate report if file was cleaned up
        analysis_resp = get_analysis_details(analysis_id, current_user, db)
        new_pdf = PDFReportGenerator.generate_report(analysis_resp.model_dump())
        if report:
            report.file_path = new_pdf
            report.file_size = os.path.getsize(new_pdf)
        else:
            report = Report(
                analysis_id=analysis_id,
                user_id=current_user.id,
                report_format="PDF",
                file_path=new_pdf,
                file_size=os.path.getsize(new_pdf)
            )
            db.add(report)
        db.commit()

    safe_name = "".join(c for c in report.analysis.app_name if c.isalnum() or c in (' ', '_', '-')).strip()
    download_filename = f"Audit_Report_{safe_name}_{report.analysis.package_name}.pdf"

    return FileResponse(
        path=report.file_path,
        media_type="application/pdf",
        filename=download_filename
    )

@router.delete("/{analysis_id}")
def delete_analysis_record(
    analysis_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    analysis = db.query(Analysis).filter(
        Analysis.id == analysis_id,
        Analysis.user_id == current_user.id
    ).first()
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    # Remove PDF files
    for r in analysis.reports:
        if r.file_path and os.path.exists(r.file_path):
            try:
                os.remove(r.file_path)
            except OSError:
                pass

    db.delete(analysis)
    db.commit()
    return {"message": "Analysis record and associated telemetry deleted successfully."}
