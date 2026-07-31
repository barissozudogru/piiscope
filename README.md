# GDPR Privacy Risk Detection Platform

This repository contains a complete, self‑hosted application for
detecting, flagging and remediating privacy risks in structured data
files.  The system was built for a European context and prioritises
compliance with the **General Data Protection Regulation (GDPR)**.

## Features

* **Multiple ingestion modes** – Upload CSV/JSON/Parquet files, paste
  free text or connect to a local database (e.g. PostgreSQL or
  SQLite) in read‑only mode.  Large files are processed in
  chunks so the application can handle datasets larger than 2 GB
  without exhausting RAM.
* **Configurable sensitivity profiles** – Built‑in profiles for
  **Medical/PHI** and **General PII** define regex patterns,
  dictionaries and severity weights.  Users can create custom
  profiles in YAML/JSON, hot‑reload them without restarting the
  service and version control their changes.
* **Hybrid detection engine** – Sensitive data is detected using
  locale‑aware regular expressions, gazetteers, dictionaries and an
  optional natural‑language model (spaCy).  Each finding records
  record ID, field name, detection rule, severity, confidence and a
  sample of the evidence.
* **Risk scoring and metrics** – The engine computes risk scores for
  columns and records based on sensitivity weight, confidence and
  prevalence.  It also calculates **k‑anonymity**, **l‑diversity** and
  **t‑closeness** on configurable quasi‑identifier sets to help
  evaluate anonymisation quality, as described in academic
  literature.
* **Remediation actions** – Users can apply hashing, nulling,
  partial redaction, generalisation, date shifting and tokenisation
  on a per‑column or per‑cell basis.  A one‑click export produces a
  sanitised file along with an audit trail of applied transforms.
* **Reports and DPIA support** – The system generates HTML/PDF
  reports summarising the dataset, detected fields, risk metrics,
  examples and remediation actions, with references to relevant
  GDPR articles and a data‑protection‑impact‑assessment (DPIA)
  template.
* **Role‑based access control (RBAC)** – Three built‑in roles
  control access to API endpoints and UI routes: **User**
  (restricted view of results), **Admin** (manage profiles and
  reports) and **Super Admin** (system and security settings).
* **Audit logging** – Every sensitive operation (login, scanning,
  export, configuration change) writes an immutable record to the
  audit log.  Logs include timestamp, user ID, action and details.
* **Secure by default** – The default configuration stores only
  metadata and findings, not raw data.  Encryption at rest and
  transport is available.  Network egress is disabled unless
  explicitly toggled by a Super Admin.  Secrets are loaded from
  environment variables.
* **React dashboard** – A React frontend presents
  summary KPIs, bar/line charts, a k‑anonymity widget, risk
  heatmaps and an FP (false positive) review queue.  The interface
  is responsive, accessible and supports keyboard navigation and
  high‑contrast modes.

## Getting started

### Prerequisites

* **Docker 20.x** and **Docker Compose v2** for containerised
  deployment.  Alternatively you can run the services directly with
  Python 3.11 and Node 18.
* **GNU Make** (optional) to simplify common commands.

### Local development

1. Clone the repository and change into the project root:

   ```bash
   git clone https://github.com/barissozudogru/data-security-checker.git
   cd data-security-checker
   ```

2. Copy the example environment file and adjust secrets:

   ```bash
   cp deploy/env.example .env
   # edit .env to set DB passwords, JWT secret, encryption key, etc.
   ```

3. Build and start the services with Docker Compose:

   ```bash
   docker compose -f deploy/docker-compose.yml up --build
   ```

   The following containers will be started:
   * **db** – PostgreSQL storing metadata, user accounts and findings.
   * **redis** – Message broker for Celery tasks.
   * **api** – FastAPI application serving the REST API.
   * **worker** – Celery worker processing scan jobs.
   * **ui** – React application served with a simple HTTP server.

4. Access the UI at `https://localhost:3000` (or `http://localhost:3000` if TLS
   is not configured).  The API documentation (Swagger UI) is available at
   `http://localhost:8000/docs`.

### Running without Docker

To run the services without Docker, install the backend and frontend
dependencies separately:

```bash
# Backend
cd api
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload

# Celery worker in another terminal
celery -A tasks.celery app worker --loglevel=info

# Frontend
cd ../app
npm install
npm start
```

The `.env` file must be loaded into both the API and worker processes.

### Example scenario

An example script demonstrating an end‑to‑end run is provided in
`tests/sample_scan_script.py`.  It logs in using the default
super‑admin account created on first run, creates a simple profile if
none exist, uploads the sample `samples/medical_notes.csv` file,
starts a scan, waits for completion, and exports a sanitised CSV.  To
run the script:

```bash
python tests/sample_scan_script.py
```

The script prints the job progress and returns a download URL for the
sanitised file.

## Repository layout

```
data-security-checker/
├── api/        – FastAPI application and detection engine
├── app/        – React frontend (dashboard, charts, file upload, etc.)
├── docs/       – Architecture description, GDPR mapping, DPIA template, threat model
├── deploy/     – Dockerfiles, docker-compose.yml, environment example
├── samples/    – Small toy datasets used for testing
└── tests/      – Unit tests for detectors and metrics
```

Refer to `docs/architecture.md` for a detailed overview of the
components and data flows.