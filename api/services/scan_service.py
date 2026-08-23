"""Scan management service.

This module handles scan job orchestration, file processing,
and results management.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .. import models
from ..exceptions import DatabaseError, ResourceNotFoundError, ValidationError
from ..logging_config import log_audit_event, log_performance_metric
from ..performance import BatchProcessor, timed
from ..validators import (
    sanitize_filename,
    validate_file_extension,
    validate_file_size,
)


class ScanService:
    """Service for managing scan operations."""

    def __init__(self, db: Session):
        self.db = db

    @timed
    def create_scan_job(
        self, user: models.User, profile_id: int, file_name: str, file_content: bytes
    ) -> models.ScanJob:
        """Create a new scan job with uploaded file."""
        try:
            # Validate profile exists
            profile = self.db.query(models.Profile).filter(models.Profile.id == profile_id).first()
            if not profile:
                raise ResourceNotFoundError(f"Profile with ID {profile_id} not found")

            # Validate file
            validate_file_size(len(file_content))
            file_extension = validate_file_extension(file_name)
            sanitized_filename = sanitize_filename(file_name)

            # Create temporary file
            temp_dir = Path(tempfile.gettempdir()) / "privacy_scans"
            temp_dir.mkdir(exist_ok=True)

            # Generate unique filename
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            unique_filename = f"{user.id}_{timestamp}_{sanitized_filename}"
            file_path = temp_dir / unique_filename

            # Write file to disk
            with open(file_path, "wb") as f:
                f.write(file_content)

            # Create scan job record
            scan_job = models.ScanJob(
                user_id=user.id,
                profile_id=profile_id,
                file_name=sanitized_filename,
                file_path=str(file_path),
                status=models.ScanStatus.PENDING,
            )

            self.db.add(scan_job)
            self.db.commit()
            self.db.refresh(scan_job)

            log_audit_event(
                action="scan_job_created",
                user_id=user.id,
                target=f"scan_job:{scan_job.id}",
                details={
                    "file_name": sanitized_filename,
                    "file_size": len(file_content),
                    "profile_id": profile_id,
                },
            )

            log_performance_metric(
                "scan_job_created", 1, file_size=len(file_content), user_id=user.id
            )

            return scan_job

        except SQLAlchemyError as e:
            self.db.rollback()
            # Clean up file if it was created
            if "file_path" in locals() and os.path.exists(file_path):
                os.remove(file_path)
            raise DatabaseError(f"Failed to create scan job: {str(e)}") from e
        except Exception:
            # Clean up file if it was created
            if "file_path" in locals() and os.path.exists(file_path):
                os.remove(file_path)
            raise

    def get_scan_job(self, job_id: int, user: models.User) -> models.ScanJob | None:
        """Get scan job by ID with permission check."""
        try:
            job = self.db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()

            if not job:
                return None

            # Check permissions
            if job.user_id != user.id and user.role not in [
                models.RoleEnum.ADMIN,
                models.RoleEnum.SUPER_ADMIN,
            ]:  # noqa: E501
                raise ValidationError("Access denied to this scan job")

            return job

        except SQLAlchemyError as e:
            raise DatabaseError(f"Failed to get scan job: {str(e)}") from e

    def update_scan_progress(
        self, job_id: int, progress: float, status: models.ScanStatus = None
    ) -> None:  # noqa: E501
        """Update scan job progress."""
        try:
            job = self.db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()

            if not job:
                raise ResourceNotFoundError(f"Scan job {job_id} not found")

            job.progress = max(0.0, min(100.0, progress))  # Clamp between 0-100

            if status:
                job.status = status

                if status == models.ScanStatus.RUNNING and not job.started_at:
                    job.started_at = datetime.now(timezone.utc)
                elif status in [
                    models.ScanStatus.COMPLETED,
                    models.ScanStatus.FAILED,
                    models.ScanStatus.CANCELLED,
                ]:  # noqa: E501
                    job.finished_at = datetime.now(timezone.utc)

            self.db.commit()

            log_performance_metric(
                "scan_progress_updated",
                progress,
                unit="percent",
                job_id=job_id,
                status=status.value if status else job.status.value,
            )

        except SQLAlchemyError as e:
            self.db.rollback()
            raise DatabaseError(f"Failed to update scan progress: {str(e)}") from e

    def add_scan_findings(self, job_id: int, findings: list[dict[str, Any]]) -> None:
        """Add findings to a scan job using batch processing."""
        try:
            # Validate job exists
            job = self.db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
            if not job:
                raise ResourceNotFoundError(f"Scan job {job_id} not found")

            # Use batch processor for efficient insertion
            def process_batch(batch_findings):
                finding_objects = [
                    models.Finding(
                        job_id=job_id,
                        record_index=finding["record_index"],
                        column_name=finding["column_name"],
                        rule_id=finding["rule_id"],
                        severity=finding["severity"],
                        confidence=finding["confidence"],
                        evidence=finding.get("evidence", "")[:255],  # Truncate evidence
                    )
                    for finding in batch_findings
                ]

                self.db.bulk_save_objects(finding_objects)
                self.db.commit()

            with BatchProcessor(batch_size=500) as processor:
                processor.set_processor(process_batch)

                for finding in findings:
                    processor.add(finding)

            log_performance_metric(
                "scan_findings_added", len(findings), unit="findings", job_id=job_id
            )

        except SQLAlchemyError as e:
            self.db.rollback()
            raise DatabaseError(f"Failed to add scan findings: {str(e)}") from e

    def set_scan_error(self, job_id: int, error_message: str) -> None:
        """Set scan job as failed with error message."""
        try:
            job = self.db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()

            if not job:
                raise ResourceNotFoundError(f"Scan job {job_id} not found")

            job.status = models.ScanStatus.FAILED
            job.error_message = error_message[:1000]  # Truncate long error messages
            job.finished_at = datetime.now(timezone.utc)

            self.db.commit()

            log_audit_event(
                action="scan_job_failed",
                user_id=job.user_id,
                target=f"scan_job:{job_id}",
                details={"error_message": error_message},
            )

        except SQLAlchemyError as e:
            self.db.rollback()
            raise DatabaseError(f"Failed to set scan error: {str(e)}") from e

    def list_user_scans(
        self,
        user: models.User,
        status: models.ScanStatus | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> list[models.ScanJob]:
        """List scan jobs for a user."""
        try:
            query = self.db.query(models.ScanJob)

            # Filter by user (admins can see all)
            if user.role not in [models.RoleEnum.ADMIN, models.RoleEnum.SUPER_ADMIN]:
                query = query.filter(models.ScanJob.user_id == user.id)

            # Filter by status if provided
            if status:
                query = query.filter(models.ScanJob.status == status)

            return (
                query.order_by(models.ScanJob.created_at.desc()).offset(offset).limit(limit).all()
            )  # noqa: E501

        except SQLAlchemyError as e:
            raise DatabaseError(f"Failed to list scan jobs: {str(e)}") from e

    def get_scan_findings(
        self,
        job_id: int,
        user: models.User,
        severity_filter: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> list[models.Finding]:
        """Get findings for a scan job."""
        try:
            # Check job access
            job = self.get_scan_job(job_id, user)
            if not job:
                raise ResourceNotFoundError(f"Scan job {job_id} not found or access denied")

            query = self.db.query(models.Finding).filter(models.Finding.job_id == job_id)

            if severity_filter:
                query = query.filter(models.Finding.severity == severity_filter)

            return (
                query.order_by(models.Finding.confidence.desc()).offset(offset).limit(limit).all()
            )  # noqa: E501

        except SQLAlchemyError as e:
            raise DatabaseError(f"Failed to get scan findings: {str(e)}") from e

    def delete_scan_job(self, job_id: int, user: models.User) -> bool:
        """Delete a scan job and its associated data."""
        try:
            job = self.get_scan_job(job_id, user)
            if not job:
                raise ResourceNotFoundError(f"Scan job {job_id} not found or access denied")

            # Delete associated file if it exists
            if job.file_path and os.path.exists(job.file_path):
                try:
                    os.remove(job.file_path)
                except OSError:
                    pass  # File might already be deleted

            # Delete job (cascade will handle findings, metrics, etc.)
            self.db.delete(job)
            self.db.commit()

            log_audit_event(
                action="scan_job_deleted",
                user_id=user.id,
                target=f"scan_job:{job_id}",
                details={"file_name": job.file_name},
            )

            return True

        except SQLAlchemyError as e:
            self.db.rollback()
            raise DatabaseError(f"Failed to delete scan job: {str(e)}") from e

    def cleanup_expired_scans(self, max_age_hours: int = 24) -> int:
        """Clean up old scan jobs and their files."""
        try:
            from datetime import timedelta

            cutoff_date = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

            # Find expired jobs
            expired_jobs = (
                self.db.query(models.ScanJob)
                .filter(
                    models.ScanJob.created_at < cutoff_date,
                    models.ScanJob.status.in_(
                        [models.ScanStatus.COMPLETED, models.ScanStatus.FAILED]
                    ),
                )
                .all()
            )

            cleaned_count = 0

            for job in expired_jobs:
                # Delete file if exists
                if job.file_path and os.path.exists(job.file_path):
                    try:
                        os.remove(job.file_path)
                    except OSError:
                        pass

                # Delete job record
                self.db.delete(job)
                cleaned_count += 1

            self.db.commit()

            log_performance_metric(
                "expired_scans_cleaned", cleaned_count, max_age_hours=max_age_hours
            )

            return cleaned_count

        except SQLAlchemyError as e:
            self.db.rollback()
            raise DatabaseError(f"Failed to cleanup expired scans: {str(e)}") from e
