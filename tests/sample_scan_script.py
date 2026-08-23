"""Sample script demonstrating an end‑to‑end scan using the API.

This script assumes that the API is running locally (e.g. via
docker‑compose) and that a default super admin user exists.  It
performs the following steps:

1. Logs in using credentials from environment variables or defaults.
2. Ensures there is at least one profile (creates a basic PII profile if none exists).
3. Uploads the sample `medical_notes.csv` file for scanning using the chosen profile.
4. Polls the job status until completion and prints progress.
5. Exports the sanitised CSV and prints the download URL.

Run this script with `python sample_scan_script.py`.  You must have the
``requests`` library installed (``pip install requests``).
"""

import os
import time

import requests

API_BASE = os.environ.get("PRIVACY_API_BASE", "http://localhost:8000")
USERNAME = os.environ.get("PRIVACY_ADMIN_USER", "admin")
PASSWORD = os.environ.get("PRIVACY_ADMIN_PASSWORD", "admin")


def main():
    # Log in
    print("Logging in...")
    resp = requests.post(
        f"{API_BASE}/auth/login",
        data={"username": USERNAME, "password": PASSWORD},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp.raise_for_status()
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    # List profiles
    print("Fetching profiles...")
    resp = requests.get(f"{API_BASE}/profiles/", headers=headers)
    resp.raise_for_status()
    profiles = resp.json()
    if profiles:
        profile_id = profiles[0]["id"]
    else:
        # Create a simple PII profile
        print("Creating default PII profile...")
        profile_def = {
            "regex_patterns": [
                {
                    "id": "email",
                    "pattern": "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}",
                    "severity": "medium",
                },
            ],
            "quasi_identifiers": ["name", "dob"],
            "sensitive_attribute": "diagnosis",
        }
        resp = requests.post(
            f"{API_BASE}/profiles/",
            headers=headers,
            json={
                "name": "Default PII",
                "version": "1.0",
                "description": "Default profile detecting emails",
                "definition": profile_def,
            },
        )
        resp.raise_for_status()
        profile_id = resp.json()["id"]
    print(f"Using profile ID {profile_id}")
    # Upload sample file
    sample_path = os.path.join(os.path.dirname(__file__), "..", "samples", "medical_notes.csv")
    print(f"Uploading {sample_path}...")
    with open(sample_path, "rb") as f:
        files = {"file": ("medical_notes.csv", f, "text/csv")}
        resp = requests.post(
            f"{API_BASE}/scan/upload",
            params={"profile_id": profile_id},
            headers=headers,
            files=files,
        )
    resp.raise_for_status()
    job = resp.json()
    job_id = job["id"]
    print(f"Job {job_id} created, waiting for completion...")
    # Poll status
    while True:
        resp = requests.get(f"{API_BASE}/scan/jobs/{job_id}", headers=headers)
        resp.raise_for_status()
        data = resp.json()
        status = data["status"]
        progress = data["progress"]
        print(f"Status: {status}, progress {progress * 100:.2f}%", end="\r")
        if status == "completed":
            break
        if status == "failed":
            print("Job failed")
            print("Error:", data.get("error_message"))
            return
        time.sleep(2)
    print("\nScan completed.")
    # Export sanitised file
    resp = requests.post(f"{API_BASE}/scan/jobs/{job_id}/export", headers=headers)
    resp.raise_for_status()
    export_info = resp.json()
    download_url = export_info.get("download_url")
    if download_url:
        print(f"Sanitised file available at: {API_BASE}{download_url}")
    else:
        print("Export did not return a download URL")


if __name__ == "__main__":
    main()
