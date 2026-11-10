import os
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Request, Response
from fastapi.responses import FileResponse, JSONResponse
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
    PolicyDiscrepancy,
    ManifestAnalysisRequest,
    ManifestAnalysisResult,
    StructuredPermissionRecord,
    PolicyAnalysisRequest,
    PolicyAnalysisResponse,
    PurposeComparisonRequest,
    ExplainableFindingRecord,
    PurposeComparisonResponse
)
from backend.security.dependencies import get_current_active_user
from backend.manifest_parser import (
    AndroidManifestParser,
    ManifestParser,
    ManifestParseError,
    ManifestSecurityError,
    XMLSizeLimitExceededError
)
from backend.policy_analyzer import PolicyAnalyzer, PolicyAnalysisError
from backend.explainability_service import ExplainabilityService
from backend.services.explanation_engine import ExplanationEngine
from backend.services.pdf_generator import PDFReportGenerator
from backend.config import settings
from backend.report_service import ReportService
from backend.services.audit_service import log_audit_event

router = APIRouter(prefix="/analysis", tags=["Analysis"])
analyze_router = APIRouter(prefix="/analyze", tags=["Manifest Extraction & Analysis"])
analyses_router = APIRouter(prefix="/analyses", tags=["Analyses Findings"])

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
    perm_records_lookup = {r["permission_name"]: r for r in parsed_manifest.get("permission_records", [])}
    for p in result.get("permissions", []):
        r_meta = perm_records_lookup.get(p["name"], {})
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
            discrepancy_status=p.get("discrepancy_status", "NORMAL"),
            declaration_type=r_meta.get("declaration_type", "uses-permission"),
            source_reference=r_meta.get("source_reference", "/manifest/uses-permission"),
            max_sdk_version=r_meta.get("max_sdk_version"),
            is_duplicate=r_meta.get("is_duplicate", False)
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

    # Commit normalized findings first so relationships are persisted
    db.commit()
    db.refresh(analysis)

    # 7. Generate comprehensive PDF report & save record to reports table
    pdf_path = ReportService.generate_pdf_report(analysis, db)
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
    db.commit()

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
    if len(content) > settings.MAX_MANIFEST_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Manifest file exceeds maximum allowable size limit of {settings.MAX_UPLOAD_SIZE_MB} MB."
        )

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
        if len(p_bytes) > settings.MAX_MANIFEST_SIZE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Privacy policy file exceeds maximum allowable size limit of {settings.MAX_UPLOAD_SIZE_MB} MB."
            )
        try:
            effective_policy = p_bytes.decode("utf-8")
        except UnicodeDecodeError:
            effective_policy = p_bytes.decode("latin-1", errors="ignore")

    if effective_policy and len(effective_policy) > settings.MAX_POLICY_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Privacy policy exceeds maximum allowable length of {settings.MAX_POLICY_LENGTH} characters."
        )

    return _process_and_save_analysis(
        manifest_xml=manifest_xml,
        policy_text=effective_policy,
        user=current_user,
        request=request,
        db=db
    )

def _execute_manifest_extraction_and_save(
    manifest_xml: str,
    source_file: str,
    privacy_policy_text: Optional[str],
    user: User,
    request: Request,
    db: Session
) -> ManifestAnalysisResult:
    # 1. Parse manifest securely via AndroidManifestParser
    try:
        parsed = AndroidManifestParser.parse(manifest_xml, source_name=source_file)
    except ManifestSecurityError as e:
        raise HTTPException(status_code=400, detail=f"Manifest Security Violation: {str(e)}")
    except ManifestParseError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse AndroidManifest.xml: {str(e)}")

    # 2. Run explanation engine to calculate risk score
    engine_result = ExplanationEngine.analyze(parsed, privacy_policy_text)

    # 3. Save to database for authenticated user
    analysis = Analysis(
        user_id=user.id,
        app_name=parsed["app_name"],
        package_name=parsed["package_name"],
        version_code=parsed.get("version_code"),
        version_name=parsed.get("version_name"),
        min_sdk=parsed.get("min_sdk"),
        target_sdk=parsed.get("target_sdk"),
        total_permissions=parsed["total_permissions"],
        dangerous_count=parsed["dangerous_count"],
        normal_count=parsed["normal_count"],
        special_count=parsed["special_count"],
        risk_score=engine_result["risk_score"],
        risk_level=engine_result["risk_level"],
        exported_components_count=parsed["exported_count"],
        raw_manifest=manifest_xml,
        raw_policy=privacy_policy_text or None
    )
    db.add(analysis)
    db.flush()

    # 4. Save structured permissions into permissions table
    structured_perm_records: List[StructuredPermissionRecord] = []
    for rec in parsed["permission_records"]:
        perm_db = Permission(
            analysis_id=analysis.id,
            name=rec["permission_name"],
            short_name=rec["permission_name"].split(".")[-1],
            permission_group=rec.get("category"),
            protection_level=rec.get("protection_level", "unknown"),
            description=rec.get("explanation") or "",
            privacy_risk="\n".join(rec.get("privacy_implications", [])) if isinstance(rec.get("privacy_implications"), list) else "",
            abuse_scenarios=rec.get("privacy_implications", []),
            severity_score=8.0 if rec.get("protection_level") == "dangerous" else (6.0 if rec.get("protection_level") in ("special", "signature/special") else 1.0),
            remediation=rec.get("platform_context") or "",
            policy_disclosed=False,
            discrepancy_status="NORMAL",
            declaration_type=rec.get("declaration_type", "uses-permission"),
            source_reference=rec.get("source_reference", "/manifest/uses-permission"),
            max_sdk_version=rec.get("max_sdk_version"),
            is_duplicate=rec.get("is_duplicate", False)
        )
        db.add(perm_db)
        structured_perm_records.append(StructuredPermissionRecord(**rec))

    db.commit()
    db.refresh(analysis)

    client_ip = request.client.host if request and request.client else "unknown"
    log_audit_event(
        db,
        action="ANALYZE_MANIFEST",
        user_id=user.id,
        resource_type="ANALYSIS",
        resource_id=str(analysis.id),
        ip_address=client_ip
    )

    return ManifestAnalysisResult(
        id=analysis.id,
        app_name=analysis.app_name,
        package_name=analysis.package_name,
        version_code=analysis.version_code,
        version_name=analysis.version_name,
        min_sdk_version=parsed.get("min_sdk"),
        target_sdk_version=parsed.get("target_sdk"),
        max_sdk_version=parsed.get("max_sdk_version"),
        total_permissions=parsed["total_permissions"],
        unique_permissions=parsed["unique_permissions"],
        duplicate_count=parsed["duplicate_count"],
        dangerous_count=parsed["dangerous_count"],
        normal_count=parsed["normal_count"],
        special_count=parsed["special_count"],
        unknown_count=parsed["unknown_count"],
        risk_score=analysis.risk_score,
        risk_level=analysis.risk_level,
        permissions=structured_perm_records,
        unsupported_declarations=parsed.get("unsupported_declarations", []),
        sdk_warnings=parsed.get("sdk_warnings", []),
        source_file=parsed.get("source_file", "AndroidManifest.xml"),
        created_at=analysis.created_at
    )

@analyze_router.post("/manifest", response_model=ManifestAnalysisResult)
def analyze_manifest_post(
    req: ManifestAnalysisRequest,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    return _execute_manifest_extraction_and_save(
        manifest_xml=req.manifest_xml,
        source_file=req.source_file or "AndroidManifest.xml",
        privacy_policy_text=req.privacy_policy_text,
        user=current_user,
        request=request,
        db=db
    )

@analyze_router.post("/manifest/upload", response_model=ManifestAnalysisResult)
async def analyze_manifest_file_upload(
    manifest_file: UploadFile = File(...),
    policy_text: Optional[str] = Form(None),
    request: Request = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    content = await manifest_file.read()
    source_filename = manifest_file.filename or "AndroidManifest.xml"
    try:
        decoded_xml, safe_name = AndroidManifestParser.validate_and_prepare_content(content, source_filename)
    except ManifestSecurityError as e:
        raise HTTPException(status_code=400, detail=f"Manifest Security Violation: {str(e)}")
    except ManifestParseError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return _execute_manifest_extraction_and_save(
        manifest_xml=decoded_xml,
        source_file=safe_name,
        privacy_policy_text=policy_text,
        user=current_user,
        request=request,
        db=db
    )

@router.post("/manifest", response_model=ManifestAnalysisResult)
def analyze_manifest_alias(
    req: ManifestAnalysisRequest,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    return _execute_manifest_extraction_and_save(
        manifest_xml=req.manifest_xml,
        source_file=req.source_file or "AndroidManifest.xml",
        privacy_policy_text=req.privacy_policy_text,
        user=current_user,
        request=request,
        db=db
    )

def _execute_policy_analysis_and_save(
    req: PolicyAnalysisRequest,
    user: User,
    request: Request,
    db: Session
) -> PolicyAnalysisResponse:
    try:
        result = PolicyAnalyzer.analyze_policy(req.policy_text, app_name=req.app_name)
    except PolicyAnalysisError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to analyze policy: {str(e)}")

    # 1. Resolve or create Analysis record
    analysis = None
    if req.analysis_id:
        analysis = db.query(Analysis).filter(
            Analysis.id == req.analysis_id,
            Analysis.user_id == user.id
        ).first()

    if not analysis:
        analysis = Analysis(
            user_id=user.id,
            app_name=req.app_name or "Privacy Policy Evaluation",
            package_name="policy.audit.standalone",
            total_permissions=0,
            dangerous_count=0,
            normal_count=0,
            special_count=0,
            risk_score=round(max(0.0, 100.0 - result["transparency_score"]), 1),
            risk_level="LOW" if result["transparency_score"] >= 70 else ("MEDIUM" if result["transparency_score"] >= 40 else "HIGH"),
            raw_policy=req.policy_text
        )
        db.add(analysis)
        db.flush()
    else:
        # Update raw_policy if linked to existing
        analysis.raw_policy = req.policy_text

    # 2. Persist extracted policy excerpts
    for domain_key, domain_data in result["domains"].items():
        disp_name = domain_data["display_name"]
        for exc in domain_data.get("excerpts", []):
            stn = exc.get("stance", "EXPLICIT_AFFIRMATIVE")
            if stn == "EXPLICIT_NEGATIVE":
                exc_type = "negation"
                sentiment = "assertive_denial"
            elif stn == "AMBIGUOUS_VAGUE":
                exc_type = "ambiguous"
                sentiment = "vague_qualifier"
            else:
                exc_type = "disclosure"
                sentiment = "affirmative_collection"

            pe = PolicyExcerpt(
                analysis_id=analysis.id,
                domain=disp_name,
                excerpt_type=exc_type,
                text_snippet=exc.get("exact_text", ""),
                sentiment_or_stance=sentiment,
                paragraph_ref=exc.get("paragraph_ref"),
                start_offset=exc.get("start_offset"),
                end_offset=exc.get("end_offset")
            )
            db.add(pe)

    db.commit()
    db.refresh(analysis)

    # 3. Audit logging
    client_ip = request.client.host if request and request.client else "unknown"
    log_audit_event(
        db,
        action="ANALYZE_POLICY",
        user_id=user.id,
        resource_type="ANALYSIS",
        resource_id=str(analysis.id),
        ip_address=client_ip
    )

    return PolicyAnalysisResponse(
        analysis_id=analysis.id,
        app_name=analysis.app_name,
        word_count=result["word_count"],
        character_count=result["character_count"],
        total_paragraphs=result["total_paragraphs"],
        transparency_score=result["transparency_score"],
        addressed_domains_count=result["addressed_domains_count"],
        missing_domains_count=result["missing_domains_count"],
        ai_augmented=result["ai_augmented"],
        ai_status=result["ai_status"],
        overall_summary=result["overall_summary"],
        domains=result["domains"],
        created_at=analysis.created_at
    )

@analyze_router.post("/policy", response_model=PolicyAnalysisResponse)
def analyze_privacy_policy_post(
    req: PolicyAnalysisRequest,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    return _execute_policy_analysis_and_save(
        req=req,
        user=current_user,
        request=request,
        db=db
    )

def _execute_purpose_comparison_and_save(
    req: PurposeComparisonRequest,
    user: User,
    request: Request,
    db: Session
) -> PurposeComparisonResponse:
    # 1. Gather permissions to evaluate
    permissions_to_eval = []
    analysis = None

    if req.analysis_id:
        analysis = db.query(Analysis).filter(
            Analysis.id == req.analysis_id,
            Analysis.user_id == user.id
        ).first()
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis record not found.")

    if req.manifest_xml and req.manifest_xml.strip():
        parsed = AndroidManifestParser.parse(req.manifest_xml)
        permissions_to_eval = parsed.get("permission_records", [])
        if not req.app_name or req.app_name == "Application":
            req.app_name = parsed.get("app_name") or req.app_name
    elif req.permissions:
        permissions_to_eval = req.permissions
    elif analysis:
        permissions_to_eval = [
            {
                "permission_name": p.name,
                "source_reference": p.source_reference or "/manifest/uses-permission",
                "source_file": "AndroidManifest.xml"
            }
            for p in analysis.permissions
        ]
    else:
        raise HTTPException(
            status_code=400,
            detail="Must supply 'permissions', 'manifest_xml', or a valid 'analysis_id'."
        )

    # 2. Run ExplainabilityService
    policy_text = req.privacy_policy_text
    if not policy_text and analysis and analysis.raw_policy:
        policy_text = analysis.raw_policy

    eval_result = ExplainabilityService.evaluate_manifest_permissions(
        permissions=permissions_to_eval,
        app_name=req.app_name or (analysis.app_name if analysis else "Application"),
        app_purpose=req.app_purpose,
        privacy_policy_text=policy_text
    )

    # 3. Create or resolve Analysis record
    if not analysis:
        analysis = Analysis(
            user_id=user.id,
            app_name=eval_result["app_name"],
            package_name="comparison.audit.app",
            total_permissions=eval_result["total_permissions"],
            dangerous_count=eval_result["risk_counts"].get("HIGH", 0),
            normal_count=eval_result["risk_counts"].get("LOW", 0),
            special_count=eval_result["risk_counts"].get("MEDIUM", 0),
            risk_score=75.0 if eval_result["overall_risk_level"] == "HIGH" else (40.0 if eval_result["overall_risk_level"] == "MEDIUM" else 10.0),
            risk_level=eval_result["overall_risk_level"],
            raw_manifest=req.manifest_xml,
            raw_policy=policy_text
        )
        db.add(analysis)
        db.flush()

    # 4. Save findings to comparison_findings and update permissions table
    ExplainabilityService.save_findings_to_db(db, analysis.id, eval_result["findings"])

    # 5. Log audit event
    client_ip = request.client.host if request and request.client else "unknown"
    log_audit_event(
        db,
        action="PURPOSE_COMPARISON",
        user_id=user.id,
        resource_type="ANALYSIS",
        resource_id=str(analysis.id),
        ip_address=client_ip
    )

    return PurposeComparisonResponse(
        analysis_id=analysis.id,
        app_name=eval_result["app_name"],
        app_purpose=eval_result["app_purpose"],
        total_permissions=eval_result["total_permissions"],
        overall_risk_level=eval_result["overall_risk_level"],
        risk_counts=eval_result["risk_counts"],
        category_counts=eval_result["category_counts"],
        policy_provided=eval_result["policy_provided"],
        findings=[ExplainableFindingRecord(**f) for f in eval_result["findings"]],
        created_at=analysis.created_at
    )

def _get_analysis_findings_response(
    analysis_id: int,
    user: User,
    db: Session
) -> PurposeComparisonResponse:
    analysis = db.query(Analysis).options(
        joinedload(Analysis.permissions),
        joinedload(Analysis.comparison_findings)
    ).filter(
        Analysis.id == analysis_id,
        Analysis.user_id == user.id
    ).first()

    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    purpose_cfs = [cf for cf in analysis.comparison_findings if cf.finding_type == "PURPOSE_COMPARISON"]
    findings_list = []

    if purpose_cfs:
        for cf in purpose_cfs:
            data = cf.matched_data if isinstance(cf.matched_data, dict) else {}
            findings_list.append(ExplainableFindingRecord(
                permission=cf.permission or data.get("permission", "unknown"),
                risk_level=cf.severity or data.get("risk_level", "LOW"),
                finding_category=cf.finding_category or data.get("finding_category", "REQUIRES_REVIEW"),
                reason=data.get("reason", f"The application declares {cf.permission}."),
                privacy_implication=data.get("privacy_implication", cf.explanation or ""),
                purpose_comparison=cf.purpose_comparison or data.get("purpose_comparison", cf.explanation or ""),
                review_question=cf.review_question or cf.remediation or "Why is this permission required?",
                evidence_source=cf.evidence_source or data.get("evidence_source", "AndroidManifest.xml"),
                source_reference=cf.source_reference or data.get("source_reference", "/manifest/uses-permission"),
                confidence=cf.confidence or data.get("confidence", "RULE_BASED")
            ))
    else:
        # Re-evaluate dynamically from permissions
        perms = [
            {"permission_name": p.name, "source_reference": p.source_reference or "/manifest/uses-permission"}
            for p in analysis.permissions
        ]
        eval_res = ExplainabilityService.evaluate_manifest_permissions(
            permissions=perms,
            app_name=analysis.app_name,
            app_purpose=None,
            privacy_policy_text=analysis.raw_policy
        )
        ExplainabilityService.save_findings_to_db(db, analysis.id, eval_res["findings"])
        findings_list = [ExplainableFindingRecord(**f) for f in eval_res["findings"]]

    risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0}
    category_counts = {
        "POTENTIALLY_EXPECTED": 0,
        "REQUIRES_REVIEW": 0,
        "PURPOSE_MISMATCH": 0,
        "UNKNOWN_PERMISSION": 0,
        "INSUFFICIENT_INFORMATION": 0
    }
    for f in findings_list:
        risk_counts[f.risk_level] = risk_counts.get(f.risk_level, 0) + 1
        cat = f.finding_category
        category_counts[cat] = category_counts.get(cat, 0) + 1

    return PurposeComparisonResponse(
        analysis_id=analysis.id,
        app_name=analysis.app_name,
        app_purpose="Stored Analysis Purpose Assessment",
        total_permissions=len(findings_list),
        overall_risk_level=analysis.risk_level,
        risk_counts=risk_counts,
        category_counts=category_counts,
        policy_provided=bool(analysis.raw_policy),
        findings=findings_list,
        created_at=analysis.created_at
    )

@analyze_router.post("/compare", response_model=PurposeComparisonResponse)
def compare_purpose_post(
    req: PurposeComparisonRequest,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    return _execute_purpose_comparison_and_save(
        req=req,
        user=current_user,
        request=request,
        db=db
    )

@router.post("/compare", response_model=PurposeComparisonResponse)
def compare_purpose_alias(
    req: PurposeComparisonRequest,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    return _execute_purpose_comparison_and_save(
        req=req,
        user=current_user,
        request=request,
        db=db
    )

@analyses_router.get("/{analysis_id}/findings", response_model=PurposeComparisonResponse)
def get_analyses_findings(
    analysis_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    return _get_analysis_findings_response(analysis_id, current_user, db)

@router.get("/{analysis_id}/findings", response_model=PurposeComparisonResponse)
def get_analysis_findings_alias(
    analysis_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    return _get_analysis_findings_response(analysis_id, current_user, db)

@router.post("/policy", response_model=PolicyAnalysisResponse)
def analyze_privacy_policy_alias(
    req: PolicyAnalysisRequest,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    return _execute_policy_analysis_and_save(
        req=req,
        user=current_user,
        request=request,
        db=db
    )

def _execute_purpose_comparison_and_save(
    req: PurposeComparisonRequest,
    user: User,
    request: Request,
    db: Session
) -> PurposeComparisonResponse:
    # 1. Gather permissions to evaluate
    permissions_to_eval = []
    analysis = None

    if req.analysis_id:
        analysis = db.query(Analysis).filter(
            Analysis.id == req.analysis_id,
            Analysis.user_id == user.id
        ).first()
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis record not found.")

    if req.manifest_xml and req.manifest_xml.strip():
        parsed = AndroidManifestParser.parse(req.manifest_xml)
        permissions_to_eval = parsed.get("permission_records", [])
        if not req.app_name or req.app_name == "Application":
            req.app_name = parsed.get("app_name") or req.app_name
    elif req.permissions:
        permissions_to_eval = req.permissions
    elif analysis:
        permissions_to_eval = [
            {
                "permission_name": p.name,
                "source_reference": p.source_reference or "/manifest/uses-permission",
                "source_file": "AndroidManifest.xml"
            }
            for p in analysis.permissions
        ]
    else:
        raise HTTPException(
            status_code=400,
            detail="Must supply 'permissions', 'manifest_xml', or a valid 'analysis_id'."
        )

    # 2. Run ExplainabilityService
    policy_text = req.privacy_policy_text
    if not policy_text and analysis and analysis.raw_policy:
        policy_text = analysis.raw_policy

    eval_result = ExplainabilityService.evaluate_manifest_permissions(
        permissions=permissions_to_eval,
        app_name=req.app_name or (analysis.app_name if analysis else "Application"),
        app_purpose=req.app_purpose,
        privacy_policy_text=policy_text
    )

    # 3. Create or resolve Analysis record
    if not analysis:
        analysis = Analysis(
            user_id=user.id,
            app_name=eval_result["app_name"],
            package_name="comparison.audit.app",
            total_permissions=eval_result["total_permissions"],
            dangerous_count=eval_result["risk_counts"].get("HIGH", 0),
            normal_count=eval_result["risk_counts"].get("LOW", 0),
            special_count=eval_result["risk_counts"].get("MEDIUM", 0),
            risk_score=75.0 if eval_result["overall_risk_level"] == "HIGH" else (40.0 if eval_result["overall_risk_level"] == "MEDIUM" else 10.0),
            risk_level=eval_result["overall_risk_level"],
            raw_manifest=req.manifest_xml,
            raw_policy=policy_text
        )
        db.add(analysis)
        db.flush()

    # 4. Save findings to comparison_findings and update permissions table
    ExplainabilityService.save_findings_to_db(db, analysis.id, eval_result["findings"])

    # 5. Log audit event
    client_ip = request.client.host if request and request.client else "unknown"
    log_audit_event(
        db,
        action="PURPOSE_COMPARISON",
        user_id=user.id,
        resource_type="ANALYSIS",
        resource_id=str(analysis.id),
        ip_address=client_ip
    )

    return PurposeComparisonResponse(
        analysis_id=analysis.id,
        app_name=eval_result["app_name"],
        app_purpose=eval_result["app_purpose"],
        total_permissions=eval_result["total_permissions"],
        overall_risk_level=eval_result["overall_risk_level"],
        risk_counts=eval_result["risk_counts"],
        category_counts=eval_result["category_counts"],
        policy_provided=eval_result["policy_provided"],
        findings=[ExplainableFindingRecord(**f) for f in eval_result["findings"]],
        created_at=analysis.created_at
    )

def _get_analysis_findings_response(
    analysis_id: int,
    user: User,
    db: Session
) -> PurposeComparisonResponse:
    analysis = db.query(Analysis).options(
        joinedload(Analysis.permissions),
        joinedload(Analysis.comparison_findings)
    ).filter(
        Analysis.id == analysis_id,
        Analysis.user_id == user.id
    ).first()

    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    purpose_cfs = [cf for cf in analysis.comparison_findings if cf.finding_type == "PURPOSE_COMPARISON"]
    findings_list = []

    if purpose_cfs:
        for cf in purpose_cfs:
            data = cf.matched_data if isinstance(cf.matched_data, dict) else {}
            findings_list.append(ExplainableFindingRecord(
                permission=cf.permission or data.get("permission", "unknown"),
                risk_level=cf.severity or data.get("risk_level", "LOW"),
                finding_category=cf.finding_category or data.get("finding_category", "REQUIRES_REVIEW"),
                reason=data.get("reason", f"The application declares {cf.permission}."),
                privacy_implication=data.get("privacy_implication", cf.explanation or ""),
                purpose_comparison=cf.purpose_comparison or data.get("purpose_comparison", cf.explanation or ""),
                review_question=cf.review_question or cf.remediation or "Why is this permission required?",
                evidence_source=cf.evidence_source or data.get("evidence_source", "AndroidManifest.xml"),
                source_reference=cf.source_reference or data.get("source_reference", "/manifest/uses-permission"),
                confidence=cf.confidence or data.get("confidence", "RULE_BASED")
            ))
    else:
        # Re-evaluate dynamically from permissions
        perms = [
            {"permission_name": p.name, "source_reference": p.source_reference or "/manifest/uses-permission"}
            for p in analysis.permissions
        ]
        eval_res = ExplainabilityService.evaluate_manifest_permissions(
            permissions=perms,
            app_name=analysis.app_name,
            app_purpose=None,
            privacy_policy_text=analysis.raw_policy
        )
        ExplainabilityService.save_findings_to_db(db, analysis.id, eval_res["findings"])
        findings_list = [ExplainableFindingRecord(**f) for f in eval_res["findings"]]

    risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0}
    category_counts = {
        "POTENTIALLY_EXPECTED": 0,
        "REQUIRES_REVIEW": 0,
        "PURPOSE_MISMATCH": 0,
        "UNKNOWN_PERMISSION": 0,
        "INSUFFICIENT_INFORMATION": 0
    }
    for f in findings_list:
        risk_counts[f.risk_level] = risk_counts.get(f.risk_level, 0) + 1
        cat = f.finding_category
        category_counts[cat] = category_counts.get(cat, 0) + 1

    return PurposeComparisonResponse(
        analysis_id=analysis.id,
        app_name=analysis.app_name,
        app_purpose="Stored Analysis Purpose Assessment",
        total_permissions=len(findings_list),
        overall_risk_level=analysis.risk_level,
        risk_counts=risk_counts,
        category_counts=category_counts,
        policy_provided=bool(analysis.raw_policy),
        findings=findings_list,
        created_at=analysis.created_at
    )

@analyze_router.post("/compare", response_model=PurposeComparisonResponse)
def compare_purpose_post(
    req: PurposeComparisonRequest,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    return _execute_purpose_comparison_and_save(
        req=req,
        user=current_user,
        request=request,
        db=db
    )

@router.post("/compare", response_model=PurposeComparisonResponse)
def compare_purpose_alias(
    req: PurposeComparisonRequest,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    return _execute_purpose_comparison_and_save(
        req=req,
        user=current_user,
        request=request,
        db=db
    )

@analyses_router.get("/{analysis_id}/findings", response_model=PurposeComparisonResponse)
def get_analyses_findings(
    analysis_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    return _get_analysis_findings_response(analysis_id, current_user, db)

@router.get("/{analysis_id}/findings", response_model=PurposeComparisonResponse)
def get_analysis_findings_alias(
    analysis_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    return _get_analysis_findings_response(analysis_id, current_user, db)

@router.get("/dashboard/metrics")
def get_dashboard_metrics(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    analyses = db.query(Analysis).filter(Analysis.user_id == current_user.id).all()
    total_analyses = len(analyses)
    total_permissions = sum(a.total_permissions for a in analyses)
    high_risks = sum(1 for a in analyses if a.risk_level in ("CRITICAL", "HIGH"))
    unknown_permissions = db.query(Permission).join(Analysis).filter(
        Analysis.user_id == current_user.id,
        Permission.protection_level == "unknown"
    ).count()

    risk_dist = {
        "CRITICAL": sum(1 for a in analyses if a.risk_level == "CRITICAL"),
        "HIGH": sum(1 for a in analyses if a.risk_level == "HIGH"),
        "MEDIUM": sum(1 for a in analyses if a.risk_level == "MEDIUM"),
        "LOW": sum(1 for a in analyses if a.risk_level == "LOW")
    }

    recent = [
        {
            "id": a.id,
            "app_name": a.app_name,
            "package_name": a.package_name,
            "risk_level": a.risk_level,
            "risk_score": a.risk_score,
            "total_permissions": a.total_permissions,
            "dangerous_count": a.dangerous_count,
            "created_at": a.created_at.isoformat() if a.created_at else None
        }
        for a in sorted(analyses, key=lambda x: x.created_at, reverse=True)[:5]
    ]

    return {
        "total_analyses": total_analyses,
        "total_permissions": total_permissions,
        "high_risks": high_risks,
        "unknown_permissions": unknown_permissions,
        "risk_distribution": risk_dist,
        "recent_analyses": recent
    }

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

def _handle_report_download(
    analysis_id: int,
    format: str,
    section: Optional[str],
    current_user: User,
    db: Session
):
    fmt = (format or "pdf").lower().strip()
    if fmt not in ("pdf", "json", "csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported format '{format}'. Supported formats: pdf, json, csv."
        )

    # 1. Ownership & record check (raises 404 or 403)
    analysis = ReportService.validate_ownership_and_get_analysis(analysis_id, current_user, db)

    # 2. Format routing
    if fmt == "pdf":
        pdf_path = ReportService.generate_pdf_report(analysis, db)
        safe_filename = ReportService.get_safe_filename(analysis.app_name, analysis.id, "pdf")

        # Track in reports table
        report_record = Report(
            analysis_id=analysis.id,
            user_id=current_user.id,
            report_format="PDF",
            file_path=pdf_path,
            file_size=os.path.getsize(pdf_path) if os.path.exists(pdf_path) else 0,
            summary_json={
                "format": "PDF",
                "risk_level": analysis.risk_level,
                "generated_at": datetime.now(timezone.utc).isoformat()
            }
        )
        db.add(report_record)
        db.commit()

        return FileResponse(
            path=pdf_path,
            media_type="application/pdf",
            filename=safe_filename
        )

    elif fmt == "json":
        json_data = ReportService.generate_json_report(analysis, db)
        safe_filename = ReportService.get_safe_filename(analysis.app_name, analysis.id, "json")

        json_filename = f"report_{analysis.id}_{uuid.uuid4().hex[:10]}.json"
        json_filepath = settings.REPORT_OUTPUT_DIR / json_filename
        with open(json_filepath, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)

        report_record = Report(
            analysis_id=analysis.id,
            user_id=current_user.id,
            report_format="JSON",
            file_path=str(json_filepath),
            file_size=os.path.getsize(json_filepath) if os.path.exists(json_filepath) else 0,
            summary_json={
                "format": "JSON",
                "risk_level": analysis.risk_level,
                "generated_at": datetime.now(timezone.utc).isoformat()
            }
        )
        db.add(report_record)
        db.commit()

        return FileResponse(
            path=str(json_filepath),
            media_type="application/json",
            filename=safe_filename
        )

    elif fmt == "csv":
        csv_content = ReportService.generate_csv_report(analysis, section=section, db=db)
        safe_filename = ReportService.get_safe_filename(analysis.app_name, analysis.id, "csv")

        csv_filename = f"report_{analysis.id}_{uuid.uuid4().hex[:10]}.csv"
        csv_filepath = settings.REPORT_OUTPUT_DIR / csv_filename
        with open(csv_filepath, "w", encoding="utf-8") as f:
            f.write(csv_content)

        report_record = Report(
            analysis_id=analysis.id,
            user_id=current_user.id,
            report_format="CSV",
            file_path=str(csv_filepath),
            file_size=os.path.getsize(csv_filepath) if os.path.exists(csv_filepath) else 0,
            summary_json={
                "format": "CSV",
                "risk_level": analysis.risk_level,
                "generated_at": datetime.now(timezone.utc).isoformat()
            }
        )
        db.add(report_record)
        db.commit()

        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'}
        )

@analyses_router.get("/{analysis_id}/report")
def get_analyses_report(
    analysis_id: int,
    format: str = "pdf",
    section: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    return _handle_report_download(analysis_id, format, section, current_user, db)

@router.get("/{analysis_id}/report")
def get_analysis_report_alias(
    analysis_id: int,
    format: str = "pdf",
    section: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    return _handle_report_download(analysis_id, format, section, current_user, db)

@router.get("/{analysis_id}/pdf")
def download_pdf_report(
    analysis_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    return _handle_report_download(analysis_id, "pdf", None, current_user, db)

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
