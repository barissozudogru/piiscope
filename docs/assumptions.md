# Assumptions & Build Plan

This document captures the key assumptions made while designing and building
the **GDPR-compliant privacy risk detection platform** described in the
project requirements.  The assumptions guide the choice of technology,
architecture, and implementation details.

## High-level assumptions

* **Local only** - The application is designed to run entirely within a
  customer-controlled environment.  There is no network egress unless an
  administrator explicitly enables it.  Models are bundled or can be
  downloaded once and cached locally.  All processing happens on local
  machines or on-premise servers.
* **European context** - The primary compliance target is the
  **General Data Protection Regulation (GDPR)**.  Feature design,
  default settings and documentation reference EU legal concepts.  The
  application does not attempt to cover every jurisdiction’s privacy
  requirements; instead it provides hooks for customisation via
  profiles and configuration.
* **Streaming processing** - Datasets may exceed the memory of a typical
  laptop (> 2 GB).  Parsers and detection routines operate on data in
  chunks.  Only metadata and findings are persisted by default; raw
  data can be encrypted at rest if explicit storage is enabled.
* **Hybrid detection** - Sensitive data is detected using a hybrid
  approach: rule-based regular expressions, dictionary/gazetteer
  look-ups and an optional natural-language model.  The bundled
  ``spacy`` model is used for named-entity recognition when available.
* **Role-based access control (RBAC)** - Every user has a role
  (Normal User, Admin or Super Admin) which determines which API
  endpoints and UI screens they may access.  Super Admins can manage
  security settings and toggle network egress.
* **Security by design** - Encryption at rest and in transit is
  implemented.  Secrets are loaded from environment variables.  A local
  TLS certificate can be configured for HTTPS.  The audit log is
  append-only.
* **Open source stack** - The backend uses **Python 3.11**,
  **FastAPI** and **Celery** for API and asynchronous processing.
  **PostgreSQL** stores metadata.  **Redis** is used as a message
  broker for Celery.  The frontend is built with **React 18** and
  **Material UI**.  Charts use **Chart.js** via
  ``react-chartjs-2``.  Docker Compose orchestrates the services.

## Step-by-step build plan

1. **Set up repository structure** - Define the directory layout with
   separate folders for the API, detection engine, worker, UI, sample
   datasets and documentation.  Include a `deploy` folder with
   Dockerfiles and a Compose file.
2. **Define database schema and models** - Create SQLAlchemy models for
   Users, Roles, Profiles, ScanJobs, Findings and AuditLogs.  Implement
   alembic migrations if desired (omitted here for brevity).
3. **Implement authentication and RBAC** - Use FastAPI’s dependency
   injection to secure routes.  Implement password hashing with
   ``passlib`` and issue JWT tokens on login.  Create decorators that
   check the authenticated user’s role before executing an endpoint.
4. **Develop detection engine** - Implement pattern definitions for
   sensitive fields (e.g. EU phone numbers, IBAN, national IDs).  Load
   dictionaries of hospital names, common drugs and personal names.
   Provide optional integration with a local spaCy model for NER.
   Write the streaming parser that reads CSV/JSON/Parquet files in
   chunks and yields detection findings.  Provide functions to
   calculate risk scores, k-anonymity, l-diversity and t-closeness.  Use
   heuristics for severity and confidence.
5. **Create Celery tasks** - Define a background task that accepts an
   uploaded file, calls the detection engine and writes results to the
   database.  Report progress through status fields on the ``ScanJob``
   model.
6. **Build REST API** - Implement endpoints for authentication,
   profile management, starting scans, querying results, computing
   metrics, retrieving recommendations, applying redactions, exporting
   sanitised data, generating reports and accessing the audit log.
7. **Design React frontend** - Set up a basic React app with routing and
   context-based authentication.  Implement pages for login, dataset
   upload, profile selection, scan status, results visualisation and
   remediation.  Use Material UI components and Chart.js for KPI
   cards, bar charts, line charts and heatmaps.  Ensure keyboard
   navigation and high-contrast modes are supported.
8. **Implement audit logging** - Whenever a user logs in, starts a scan,
   views sensitive data, exports a dataset or changes configuration,
   append a record to the audit log with timestamp, user ID, action
   name and details.  Expose an endpoint for Admins to query logs.
9. **Generate reports** - Create a report builder that compiles
   detected fields, sample findings, risk scores, applied
   transformations and GDPR references into an HTML document.  Use
   ``weasyprint`` or ``pdfkit`` to render the HTML to PDF.
10. **Write unit and integration tests** - Test the detection patterns,
    metric calculations and redaction functions.  Provide a sample
    script that runs an end-to-end scan on the toy dataset and
    demonstrates export and report generation.

These steps align with the architecture and design documents found in the
`docs` folder.  Subsequent sections of the repository provide concrete
implementations following this plan.