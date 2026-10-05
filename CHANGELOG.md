# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.0] - 2026-08-26

### Added

- A 512-row, multilingual, privacy-safe structured PII pattern benchmark with deterministic generation, checked-in evaluation results, and a Hugging Face dataset card.
- Regression coverage for international phone boundaries, malformed IPv6 values, and cross-detector false positives.

### Fixed

- International telephone numbers beginning with `+` are now detected without relying on an invalid word boundary.
- Turkish phone rules no longer absorb North American numbers.
- The IPv6 rule no longer emits a valid-looking prefix from a malformed address.
- IP address columns no longer emit overlapping date findings, and VAT columns no longer emit generic passport findings.
- Generic passport matching is now case-sensitive.

## [1.2.0] - 2026-08-26

### Added

- SARIF 2.1.0 output for privacy findings without matched or redacted sample values.
- Reusable GitHub Action that creates a SARIF artifact and enforces a configurable risk threshold.
- Petri Labs discovery page, PyPI download badge, and a repository social preview.

### Changed

- Package homepage and documentation links now point to the focused Petri Labs tool page while source and issues remain on GitHub.

## [1.1.1] - 2026-08-23

### Changed

- Citation metadata and package version for Zenodo archiving.

## [1.1.0] - 2026-08-23

First public release under the piiscope name, and the first release on PyPI.

### Added
- Standalone `piiscope` package and CLI.
- Python API for integrating into other applications.
- Multi-jurisdiction detectors for GDPR, CCPA, KVKK, and LGPD.
- Risk scoring metrics including k-anonymity, l-diversity, and t-closeness.
- Remediation strategies and reports.
- Reference server using FastAPI and Celery with RBAC, audit log, webhooks, and compliance reports.
- Docker deployment support.

### Security
- Upgraded dependencies: python-jose, python-multipart, jinja2, cryptography, and starlette.
- Fixed startup defects.

## [1.0.0] - 2026-03-12

Initial release of the GDPR privacy risk detection platform (private): FastAPI
API, Celery worker, PostgreSQL, Redis and React UI with detection, k-anonymity
metrics, remediation, RBAC, audit log and compliance reports.
