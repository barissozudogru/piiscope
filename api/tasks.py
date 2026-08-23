"""Celery tasks for long-running operations such as scanning files.

Each task receives a job ID, loads the corresponding record from the
database, invokes the detection engine and writes findings back to
the database incrementally. Metrics are computed at the end and
stored on the `metrics` table.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import pandas as pd
from celery import Celery
from sqlalchemy.orm import Session

from piiscope.detection.engine import DetectionEngine, Finding
from piiscope.metrics.metrics import (
    compute_k_anonymity,
    compute_l_diversity,
    compute_reidentification_risk,
    compute_t_closeness,
    generate_privacy_impact_assessment,
)

from . import models
from .config import settings
from .database import SessionLocal

celery_app = Celery(__name__, broker=settings.redis_url, backend=settings.redis_url)


@celery_app.task(bind=True)
def scan_file_task(self, job_id: int) -> dict[str, Any] | None:
    """Celery task to scan an uploaded file for sensitive data.

    The task retrieves the job and profile from the database, creates a
    detection engine, streams the file and writes findings and metrics.

    Key behavioural changes vs the original implementation:
      - Row values for metric computation are collected in memory during
        the streaming pass rather than re-reading the file per row
        (eliminates the O(n^2) get_row_values bottleneck).
      - Privacy impact assessment (PIA) and re-identification risk are
        computed and stored in the Metric record.
      - PII categories from findings are collected and used to populate
        masking recommendations.
    """
    db: Session = SessionLocal()
    try:
        job: models.ScanJob = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
        if not job:
            raise ValueError(f"ScanJob {job_id} not found")

        job.status = models.ScanStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)
        db.commit()

        profile = job.profile.definition
        engine_det = DetectionEngine(profile)
        file_path = job.file_path
        if file_path is None:
            job.status = models.ScanStatus.FAILED
            job.error_message = "Database source scans are not yet supported in this task runner."
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
            return {"error": job.error_message}

        file_format = os.path.splitext(file_path)[1].lstrip(".").lower()

        qi: list[str] = profile.get("quasi_identifiers") or []
        sensitive_attr: str | None = profile.get("sensitive_attribute")

        # Estimate total row count for progress reporting
        total_rows: int | None = None
        try:
            if file_format in ("csv", "json"):
                with open(file_path, encoding="utf-8", errors="ignore") as f:
                    total_rows = sum(1 for _ in f)
        except OSError:
            total_rows = None

        processed_rows = 0

        # Collect quasi-identifier + sensitive-attribute values during the
        # streaming pass so we don't re-read the file per row.
        # Structure: {record_index: {col: value}}
        qi_rows: dict[int, dict[str, Any]] = {}
        pii_categories_seen: set[str] = set()

        def callback(record_index: int, findings: list[Finding]) -> None:
            nonlocal processed_rows

            for f in findings:
                # Collect PII categories for masking recommendations
                pdef = engine_det.patterns.get(f.rule_id)
                if pdef and hasattr(pdef, "pii_category"):
                    pii_categories_seen.add(pdef.pii_category)

                db.add(
                    models.Finding(
                        job_id=job.id,
                        record_index=f.record_index,
                        column_name=f.column_name,
                        rule_id=f.rule_id,
                        severity=str(f.severity),
                        confidence=f.confidence,
                        evidence=f.evidence,
                        finding_metadata=f.metadata if f.metadata else None,
                    )
                )
            db.commit()

            # Update progress
            processed_rows += 1
            if total_rows:
                job.progress = min(99.0, processed_rows / total_rows * 100.0)
                db.commit()

        # ------------------------------------------------------------------
        # Perform scanning; collect row values for metrics in the same pass
        # ------------------------------------------------------------------
        # We monkey-patch scan_row temporarily to also stash QI values.
        # This is cleaner than modifying DetectionEngine for a task concern.
        original_scan_row = engine_det.scan_row

        sampled_metrics = False

        def scan_row_with_collection(row: dict[str, Any], record_index: int):
            nonlocal sampled_metrics
            # Stash QI and sensitive-attr values for metrics computation
            if qi or sensitive_attr:
                if len(qi_rows) < settings.metrics_sample_rows:
                    row_slice: dict[str, Any] = {}
                    for col in qi:
                        if col in row:
                            row_slice[col] = row[col]
                    if sensitive_attr and sensitive_attr in row:
                        row_slice[sensitive_attr] = row[sensitive_attr]
                    if row_slice:
                        qi_rows[record_index] = row_slice
                else:
                    sampled_metrics = True
            return original_scan_row(row, record_index)

        engine_det.scan_row = scan_row_with_collection  # type: ignore[method-assign]

        try:
            engine_det.scan_file(file_path, file_format, callback)
            job.status = models.ScanStatus.COMPLETED
        except Exception as exc:
            job.status = models.ScanStatus.FAILED
            job.error_message = str(exc)
        finally:
            job.progress = 1.0
            job.finished_at = datetime.now(timezone.utc)
            db.commit()

        # ------------------------------------------------------------------
        # Compute anonymisation metrics
        # ------------------------------------------------------------------
        k = l_val = None
        t: float | None = None
        reidentification: dict[str, Any] | None = None
        pia: dict[str, Any] | None = None

        if qi and qi_rows:
            try:
                # Build a DataFrame from the collected QI rows
                columns_needed = list(qi)
                if sensitive_attr:
                    columns_needed.append(sensitive_attr)
                df_metrics = pd.DataFrame.from_dict(qi_rows, orient="index")
                # Keep only available columns
                columns_needed = [c for c in columns_needed if c in df_metrics.columns]
                df_metrics = df_metrics[columns_needed]

                k = compute_k_anonymity(df_metrics, qi)
                if sensitive_attr and sensitive_attr in df_metrics.columns:
                    l_val = compute_l_diversity(df_metrics, qi, sensitive_attr)
                    t = compute_t_closeness(df_metrics, qi, sensitive_attr)

                reidentification = compute_reidentification_risk(df_metrics, qi)

            except Exception as exc:
                import logging

                logging.getLogger(__name__).warning(
                    "Metrics computation failed for job %s: %s", job_id, exc
                )

        # Build PIA summary
        try:
            total_findings = (
                db.query(models.Finding).filter(models.Finding.job_id == job_id).count()
            )
            highest_severity_row = (
                db.query(models.Finding)
                .filter(models.Finding.job_id == job_id)
                .order_by(models.Finding.confidence.desc())
                .first()
            )

            highest_sev = 0.0
            if highest_severity_row:
                try:
                    highest_sev = float(highest_severity_row.severity)
                except (ValueError, TypeError):
                    highest_sev = 0.0

            rules_triggered = [
                row[0]
                for row in db.query(models.Finding.rule_id)
                .filter(models.Finding.job_id == job_id)
                .distinct()
                .all()
            ]

            pia = generate_privacy_impact_assessment(
                findings_summary={
                    "total_findings": total_findings,
                    "pii_categories": list(pii_categories_seen),
                    "highest_severity": highest_sev,
                    "rules_triggered": rules_triggered,
                },
                k_anonymity=k,
                l_diversity=l_val,
                t_closeness=t,
                reidentification_risk=reidentification,
            )
        except Exception as exc:
            import logging

            logging.getLogger(__name__).warning("PIA generation failed for job %s: %s", job_id, exc)

        # Persist metrics
        existing = db.query(models.Metric).filter(models.Metric.job_id == job_id).first()
        if existing:
            existing.quasi_identifiers = qi if qi else None
            existing.k_anonymity = k
            existing.l_diversity = l_val
            existing.t_closeness = t
            existing.reidentification_risk = reidentification
            existing.privacy_impact_assessment = pia
        else:
            metric = models.Metric(
                job_id=job.id,
                quasi_identifiers=qi if qi else None,
                k_anonymity=k,
                l_diversity=l_val,
                t_closeness=t,
                reidentification_risk=reidentification,
                privacy_impact_assessment=pia,
            )
            db.add(metric)
        db.commit()

        if sampled_metrics:
            if pia is not None:
                pia["metrics_sampled"] = True
                pia["metrics_sample_rows"] = settings.metrics_sample_rows

            existing = db.query(models.Metric).filter(models.Metric.job_id == job_id).first()
            if existing:
                existing.privacy_impact_assessment = pia
                db.commit()

        return {"metrics_sampled": sampled_metrics} if sampled_metrics else None

    finally:
        db.close()
