# GDPR Privacy Risk Detection Platform

This repository contains a complete, self‑hosted application for
detecting, flagging and remediating privacy risks in structured data
files.  The system was built for a European context and prioritises
compliance with the **General Data Protection Regulation (GDPR)**.

## Capabilities

The platform ingests CSV, JSON, Parquet files, free text, or SQL databases (PostgreSQL, SQLite) in read-only mode, processing large files in chunks. Sensitive data is detected using regular expressions, gazetteers, dictionaries, and optional spaCy models.

Risk metrics include k-anonymity, l-diversity, and t-closeness calculated on quasi-identifier sets. Remediation options include hashing, nulling, redaction, generalisation, date shifting, and tokenisation, with HTML and PDF report generation for DPIA documentation.

Built-in role-based access control (User, Admin, Super Admin) manages system access, while immutable audit logs record sensitive actions. A React frontend provides summary charts, risk heatmaps, and a false-positive review queue.

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