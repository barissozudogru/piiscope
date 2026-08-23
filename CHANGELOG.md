# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-08-23

This is the first public release of the project under the new piiscope brand.

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
