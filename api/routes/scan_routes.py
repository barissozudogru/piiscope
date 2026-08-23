"""Scan job management and data export endpoints.

These endpoints allow users to upload datasets for scanning, check the
status and results of a scan, retrieve metrics and export a
sanitised version of the original data.  File uploads are stored on
disk; scanning is performed asynchronously via Celery.  All routes
require authentication; permissions depend on the user's role.
"""

from __future__ import annotations

import os
import re

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from piiscope.detection.classifier import DataClassifier
from piiscope.metrics.risk_scorer import RiskScorer
from piiscope.remediation import masking

from .. import auth, models, schemas
from ..audit import log_audit_event
from ..config import settings
from ..database import get_db
from ..exceptions import ValidationError
from ..services.compliance_report import ComplianceReportGenerator
from ..services.remediation import RemediationService
from ..tasks import scan_file_task
from ..validators import validate_file_extension

router = APIRouter()


UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "uploads")
EXPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "exports")
REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(EXPORT_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)


@router.get("/jobs", response_model=list[schemas.ScanJobOut])
async def list_jobs(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
) -> list[schemas.ScanJobOut]:
    """List scan jobs for the current user (or all jobs if admin/superadmin)."""
    if current_user.role in (models.RoleEnum.ADMIN, models.RoleEnum.SUPER_ADMIN):
        jobs = db.query(models.ScanJob).order_by(models.ScanJob.created_at.desc()).all()
    else:
        jobs = (
            db.query(models.ScanJob)
            .filter(models.ScanJob.user_id == current_user.id)
            .order_by(models.ScanJob.created_at.desc())
            .all()
        )
    return [schemas.ScanJobOut.model_validate(j) for j in jobs]


@router.post("/upload", response_model=schemas.ScanJobOut, status_code=status.HTTP_201_CREATED)
async def upload_dataset(
    profile_id: int = Query(..., description="ID of the sensitivity profile to use"),
    file: UploadFile = File(..., description="Dataset file (CSV, JSON or Parquet)"),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(
        auth.role_required(models.RoleEnum.USER, models.RoleEnum.ADMIN, models.RoleEnum.SUPER_ADMIN)
    ),  # noqa: E501
) -> schemas.ScanJobOut:
    """Upload a dataset and create a scan job.

    The uploaded file is saved to the local ``uploads`` directory with a
    unique name.  A ``ScanJob`` record is created with status
    ``PENDING`` and a Celery task is triggered to process the file.
    """
    # Check profile exists
    profile = db.query(models.Profile).get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    # Validate file extension before accepting the upload
    try:
        validate_file_extension(file.filename or "")
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Stream upload while enforcing the configured size limit
    max_bytes = settings.max_file_size_mb * 1024 * 1024
    suffix = os.path.splitext(file.filename)[1]
    unique_name = f"{current_user.id}_{profile_id}_{os.urandom(8).hex()}{suffix}"
    file_path = os.path.join(UPLOAD_DIR, unique_name)

    from ..utils import stream_upload_to_disk

    try:
        await stream_upload_to_disk(file, file_path, max_bytes)
    except ValidationError as exc:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum allowed size of {settings.max_file_size_mb} MB",
        ) from exc
    except Exception as exc:
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(status_code=500, detail=f"Failed to save uploaded file: {exc}") from exc
    # Create scan job record
    job = models.ScanJob(
        user_id=current_user.id,
        profile_id=profile_id,
        file_name=file.filename,
        file_path=file_path,
        status=models.ScanStatus.PENDING,
        progress=0.0,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    # Trigger Celery task asynchronously
    scan_file_task.delay(job.id)
    # Audit log
    log_audit_event(
        db,
        current_user.id,
        action="scan_started",
        target=f"job:{job.id}",
        details={"file_name": file.filename, "profile_id": profile_id},
    )  # noqa: E501
    return schemas.ScanJobOut.model_validate(job)


@router.get("/jobs/{job_id}", response_model=schemas.ScanJobOut)
async def get_job(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
) -> schemas.ScanJobOut:
    """Retrieve details of a scan job.  Users may only see their own jobs
    unless they have admin privileges."""
    job = db.query(models.ScanJob).get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    # Authorisation: normal users can only access their own jobs; admins can access all
    if current_user.role == models.RoleEnum.USER and job.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorised to view this job")
    return schemas.ScanJobOut.model_validate(job)


@router.get("/jobs/{job_id}/findings", response_model=list[schemas.FindingOut])
async def list_findings(
    job_id: int,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
) -> list[schemas.FindingOut]:
    """List findings for a specific job.  Supports pagination via skip/limit."""
    job = db.query(models.ScanJob).get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if current_user.role == models.RoleEnum.USER and job.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorised to view this job")
    findings = (
        db.query(models.Finding)
        .filter(models.Finding.job_id == job_id)
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [schemas.FindingOut.model_validate(f) for f in findings]


@router.get("/jobs/{job_id}/metrics", response_model=schemas.MetricOut)
async def get_metrics(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
) -> schemas.MetricOut:
    """Retrieve anonymisation metrics for a job."""
    job = db.query(models.ScanJob).get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if current_user.role == models.RoleEnum.USER and job.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorised to view this job")
    metric = db.query(models.Metric).filter(models.Metric.job_id == job_id).first()
    if not metric:
        raise HTTPException(status_code=404, detail="Metrics not available yet")
    return schemas.MetricOut.model_validate(metric)


@router.post("/jobs/{job_id}/export", status_code=status.HTTP_201_CREATED)
async def export_sanitised(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
) -> dict:
    """Create and download a sanitised version of the scanned dataset.

    This simplistic implementation reads the original file into memory,
    applies any masks defined for the job and writes a CSV to the
    ``exports`` directory.  The API returns a download URL.  In a
    production environment this operation should stream data rather than
    loading it fully into memory.
    """
    job = db.query(models.ScanJob).get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if current_user.role == models.RoleEnum.USER and job.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorised to export this job")
    if job.status != models.ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Job not completed")
    file_ext = os.path.splitext(job.file_path)[1].lower()
    # Load the file into DataFrame
    import pandas as pd  # type: ignore

    if file_ext == ".csv":
        df = pd.read_csv(job.file_path, dtype=str, keep_default_na=False)
    elif file_ext == ".json":
        df = pd.read_json(job.file_path, lines=True, dtype=str)
    else:
        raise HTTPException(status_code=400, detail="Unsupported file format for export")
    # Apply masks (here we simply null out columns indicated in Mask table)
    masks = db.query(models.Mask).filter(models.Mask.job_id == job_id).all()
    for m in masks:
        if m.mask_type == "null":
            df[m.column_name] = None
        elif m.mask_type == "hash":
            df[m.column_name] = df[m.column_name].apply(lambda x: masking.hash_value(x))
        elif m.mask_type == "redact":
            df[m.column_name] = df[m.column_name].apply(
                lambda x: masking.partial_redact(x) if isinstance(x, str) else x
            )  # noqa: E501
        # Additional mask types can be added here
    # Write sanitised file
    out_name = f"job_{job_id}_sanitised.csv"
    out_path = os.path.join(EXPORT_DIR, out_name)
    df.to_csv(out_path, index=False)
    # Record audit event and create report entry
    report = models.Report(job_id=job.id, html_path=out_path)
    db.add(report)
    db.commit()
    # Audit log
    log_audit_event(
        db,
        current_user.id,
        action="export_sanitised",
        target=f"job:{job.id}",
        details={"output_path": out_path},
    )  # noqa: E501
    # Return a link to download
    return {"download_url": f"/scan/download/{out_name}"}


@router.patch(
    "/jobs/{job_id}/findings/{finding_id}/false-positive", response_model=schemas.FindingOut
)  # noqa: E501
async def mark_finding_false_positive(
    job_id: int,
    finding_id: int,
    is_false_positive: bool = True,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
) -> schemas.FindingOut:
    """Mark or unmark a finding as a false positive.

    False positive findings are preserved in the database but excluded
    from risk scores and compliance reports. Set is_false_positive=false
    to reinstate a previously dismissed finding.
    """
    job = db.query(models.ScanJob).get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if current_user.role == models.RoleEnum.USER and job.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorised to modify this job")
    finding = (
        db.query(models.Finding)
        .filter(models.Finding.id == finding_id, models.Finding.job_id == job_id)
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding.is_false_positive = is_false_positive
    db.commit()
    db.refresh(finding)
    log_audit_event(
        db,
        current_user.id,
        action="finding_false_positive_updated",
        target=f"finding:{finding_id}",
        details={"is_false_positive": is_false_positive},
    )
    return schemas.FindingOut.model_validate(finding)


@router.get("/jobs/{job_id}/metrics/privacy-impact", response_model=dict)
async def get_privacy_impact_assessment(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
) -> dict:
    """Retrieve the full Privacy Impact Assessment for a completed scan job.

    Returns the PIA generated during scanning, including compliance gaps,
    masking recommendations, jurisdiction applicability and re-identification
    risk scores.
    """
    job = db.query(models.ScanJob).get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if current_user.role == models.RoleEnum.USER and job.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorised to view this job")
    metric = db.query(models.Metric).filter(models.Metric.job_id == job_id).first()
    if not metric or not metric.privacy_impact_assessment:
        raise HTTPException(status_code=404, detail="Privacy impact assessment not available")
    return metric.privacy_impact_assessment


@router.get("/jobs/{job_id}/compliance-report")
async def get_compliance_report(
    job_id: int,
    format: str = "json",
    organisation: str = "Organisation",
    data_controller: str = "Data Controller",
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
) -> dict:
    """Generate a GDPR Article 30 / DPIA compliance report for a completed scan.

    Supported ``format`` values: ``json``, ``html``, ``markdown``.
    Returns JSON when ``format=json``; for ``html`` and ``markdown`` the
    rendered string is wrapped in a JSON envelope under the key ``content``.
    """
    job = db.query(models.ScanJob).get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if current_user.role == models.RoleEnum.USER and job.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorised to view this job")
    if job.status != models.ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Job not completed yet")

    # Fetch all non-false-positive findings
    findings_orm = (
        db.query(models.Finding)
        .filter(models.Finding.job_id == job_id, models.Finding.is_false_positive == False)  # noqa: E712
        .all()
    )
    findings = [
        {
            "id": f.id,
            "rule_id": f.rule_id,
            "column_name": f.column_name,
            "severity": f.severity,
            "confidence": f.confidence,
            "pii_category": (f.finding_metadata or {}).get("pii_category", ""),
        }
        for f in findings_orm
    ]

    # Classify findings
    classifier = DataClassifier()
    classified = classifier.classify_scan(findings)
    inventory = classifier.inventory_to_dict(classifier.build_inventory(classified))

    # Score scan
    scorer = RiskScorer(context="database_field", jurisdictions=["gdpr"])
    risk_summary = scorer.score_scan(job_id, findings)
    risk_dict = {
        "aggregate_score": risk_summary.aggregate_score,
        "max_score": risk_summary.max_score,
        "critical_count": risk_summary.critical_count,
        "high_count": risk_summary.high_count,
        "medium_count": risk_summary.medium_count,
        "low_count": risk_summary.low_count,
        "top_rule_ids": risk_summary.top_rule_ids,
    }

    # Compute per-finding risk scores for remediation prioritisation
    finding_scores = {fs.rule_id: fs.final_score for fs in risk_summary.scored_findings}
    risk_scores_by_id = {f["id"]: finding_scores.get(f["rule_id"], 5.0) for f in findings}

    # Generate remediation suggestions
    remediation_svc = RemediationService()
    suggestions = remediation_svc.suggest_for_scan(findings, risk_scores_by_id)
    suggestion_dicts = [remediation_svc.to_dict(s) for s in suggestions]

    # Generate compliance report
    generator = ComplianceReportGenerator()
    report_str = generator.generate(
        scan_id=job_id,
        findings=findings,
        classified_inventory=inventory,
        risk_summary=risk_dict,
        suggestions=suggestion_dicts,
        format=format,
        organisation=organisation,
        data_controller=data_controller,
    )

    log_audit_event(
        db,
        current_user.id,
        action="compliance_report_generated",
        target=f"job:{job_id}",
        details={"format": format},
    )

    if format.lower() == "json":
        import json as _json

        return _json.loads(report_str)
    return {"format": format, "content": report_str}


@router.get("/download/{file_name}")
async def download_file(
    file_name: str,
    current_user: models.User = Depends(auth.get_current_user),
) -> FileResponse:
    """Serve a sanitised export file from the exports directory.

    Requires authentication.  The resolved path is validated to be within
    EXPORT_DIR to prevent path traversal attacks.  Only safe filename
    characters are accepted.
    """
    # Reject filenames containing directory separators or non-safe characters.
    if not re.match(r"^[A-Za-z0-9_\-]+\.csv$", file_name):
        raise HTTPException(status_code=400, detail="Invalid file name")

    resolved = os.path.realpath(os.path.join(EXPORT_DIR, file_name))
    export_dir_resolved = os.path.realpath(EXPORT_DIR)

    # Ensure the resolved path stays within EXPORT_DIR (prevent traversal).
    if not resolved.startswith(export_dir_resolved + os.sep) and resolved != export_dir_resolved:
        raise HTTPException(status_code=400, detail="Invalid file name")

    if not os.path.isfile(resolved):
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(resolved, filename=file_name, media_type="text/csv")
