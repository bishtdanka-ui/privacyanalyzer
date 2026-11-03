import os
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.user import User
from backend.models.analysis import AnalysisRecord
from backend.schemas.analysis import (
    ManifestTextAnalysisRequest,
    AnalysisResponse,
    AnalysisSummary
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
    # 1. Parse manifest
    try:
        parsed_manifest = ManifestParser.parse_xml_content(manifest_xml)
    except ManifestParseError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse XML: {str(e)}")

    # 2. Run explanation engine
    result = ExplanationEngine.analyze(parsed_manifest, policy_text)

    # 3. Generate PDF report
    pdf_path = PDFReportGenerator.generate_report(result)
    result["pdf_report_path"] = pdf_path

    # 4. Save to database
    record = AnalysisRecord(
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
        manifest_data={
            "permissions": result["permissions"],
            "target_sdk_warnings": result["target_sdk_warnings"]
        },
        policy_data=result.get("policy_analysis"),
        discrepancy_data={
            "discrepancies": result.get("discrepancies"),
            "combos": result.get("combo_findings")
        },
        pdf_report_path=pdf_path
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    result["id"] = record.id
    result["created_at"] = record.created_at

    client_ip = request.client.host if request.client else "unknown"
    log_audit_event(
        db,
        action="RUN_ANALYSIS",
        user_id=user.id,
        target_type="ANALYSIS",
        target_id=str(record.id),
        details={
            "package_name": record.package_name,
            "risk_score": record.risk_score,
            "risk_level": record.risk_level
        },
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
    """
    Analyze raw AndroidManifest.xml string with optional privacy policy text.
    """
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
    """
    Upload an AndroidManifest.xml file and optional privacy policy document/text.
    """
    content = await manifest_file.read()
    try:
        manifest_xml = content.decode("utf-8")
    except UnicodeDecodeError:
        try:
            manifest_xml = content.decode("latin-1")
        except Exception:
            raise HTTPException(status_code=400, detail="Uploaded manifest file must be a readable UTF-8 or Latin-1 XML file.")

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
    """
    Retrieve all past analysis records performed by the logged-in user.
    """
    records = db.query(AnalysisRecord).filter(
        AnalysisRecord.user_id == current_user.id
    ).order_by(AnalysisRecord.created_at.desc()).all()
    return records

@router.get("/{analysis_id}", response_model=AnalysisResponse)
def get_analysis_details(
    analysis_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Retrieve full explainable report details for a specific analysis record.
    """
    record = db.query(AnalysisRecord).filter(
        AnalysisRecord.id == analysis_id,
        AnalysisRecord.user_id == current_user.id
    ).first()
    
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    m_data = record.manifest_data or {}
    disc_data = record.discrepancy_data or {}
    
    return AnalysisResponse(
        id=record.id,
        app_name=record.app_name,
        package_name=record.package_name,
        version_code=record.version_code,
        version_name=record.version_name,
        min_sdk=record.min_sdk,
        target_sdk=record.target_sdk,
        total_permissions=record.total_permissions,
        dangerous_count=record.dangerous_count,
        normal_count=record.normal_count,
        special_count=record.special_count,
        risk_score=record.risk_score,
        risk_level=record.risk_level,
        exported_components_count=record.exported_components_count,
        target_sdk_warnings=m_data.get("target_sdk_warnings", []),
        permissions=m_data.get("permissions", []),
        combo_findings=disc_data.get("combos", []),
        discrepancies=disc_data.get("discrepancies", []),
        policy_analysis=record.policy_data,
        pdf_report_path=record.pdf_report_path,
        created_at=record.created_at
    )

@router.get("/{analysis_id}/pdf")
def download_pdf_report(
    analysis_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Download the generated PDF audit report.
    """
    record = db.query(AnalysisRecord).filter(
        AnalysisRecord.id == analysis_id,
        AnalysisRecord.user_id == current_user.id
    ).first()

    if not record or not record.pdf_report_path:
        raise HTTPException(status_code=404, detail="PDF report not found for this record.")

    pdf_file = Path(record.pdf_report_path)
    if not pdf_file.exists():
        # Re-generate if missing
        m_data = record.manifest_data or {}
        disc_data = record.discrepancy_data or {}
        analysis_dict = {
            "app_name": record.app_name,
            "package_name": record.package_name,
            "version_name": record.version_name,
            "version_code": record.version_code,
            "min_sdk": record.min_sdk,
            "target_sdk": record.target_sdk,
            "total_permissions": record.total_permissions,
            "dangerous_count": record.dangerous_count,
            "risk_score": record.risk_score,
            "risk_level": record.risk_level,
            "exported_components_count": record.exported_components_count,
            "target_sdk_warnings": m_data.get("target_sdk_warnings", []),
            "permissions": m_data.get("permissions", []),
            "combo_findings": disc_data.get("combos", []),
            "discrepancies": disc_data.get("discrepancies", [])
        }
        new_pdf = PDFReportGenerator.generate_report(analysis_dict)
        record.pdf_report_path = new_pdf
        db.commit()
        pdf_file = Path(new_pdf)

    safe_app_name = "".join(c for c in record.app_name if c.isalnum() or c in (' ', '_', '-')).strip()
    download_filename = f"Audit_Report_{safe_app_name}_{record.package_name}.pdf"

    return FileResponse(
        path=str(pdf_file),
        media_type="application/pdf",
        filename=download_filename
    )

@router.delete("/{analysis_id}")
def delete_analysis_record(
    analysis_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Delete an analysis record and clean up its stored PDF.
    """
    record = db.query(AnalysisRecord).filter(
        AnalysisRecord.id == analysis_id,
        AnalysisRecord.user_id == current_user.id
    ).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    if record.pdf_report_path and os.path.exists(record.pdf_report_path):
        try:
            os.remove(record.pdf_report_path)
        except OSError:
            pass

    db.delete(record)
    db.commit()
    return {"message": "Analysis record deleted successfully."}
