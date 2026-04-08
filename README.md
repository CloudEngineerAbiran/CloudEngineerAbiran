# cloud-vulnerability-scanner

A production-oriented **Cloud Vulnerability Management Platform** for AWS that discovers high-risk cloud misconfigurations, stores findings, and generates reports through API and CLI workflows.

## Architecture

```text
User → FastAPI API → Scanner Engine → AWS APIs → Findings DB → Report Generator
```

## Features

- AWS scanning with `boto3` for:
  - **S3** public ACL exposure
  - **IAM** wildcard trust principals + AdministratorAccess role attachments
  - **EC2** internet-exposed risky ports via Security Groups
- CVSS-like risk scoring and severity normalization (Critical/High/Medium/Low)
- Persistent finding storage using SQLite (or PostgreSQL via `DATABASE_URL`)
- REST API with FastAPI
- CLI scanner execution script for automation jobs
- Report generation in JSON + human-readable TXT
- CI pipeline using GitHub Actions (`ruff` + `pytest`)
- Config via `.env` and optional YAML config file

## Why this matters (vs Qualys / Tenable)

Enterprise tools like Qualys and Tenable provide broad asset coverage and compliance packs. This project demonstrates a lightweight, extensible cloud-native scanner that can be tailored for organization-specific AWS risks, custom scoring logic, and internal workflows.

## Project Structure

```text
project-root/
 ├── app/
 │   ├── main.py
 │   ├── scanner/
 │   ├── services/
 │   ├── models/
 │   └── utils/
 ├── scripts/
 ├── tests/
 ├── terraform/
 ├── requirements.txt
 ├── .env.example
 ├── config.example.yaml
 ├── README.md
 └── .github/workflows/
```

## Setup

1. **Create venv and install dependencies**
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. **Configure settings**
   ```bash
   cp .env.example .env
   cp config.example.yaml config.yaml
   # edit values as needed
   ```
3. **Run API**
   ```bash
   uvicorn app.main:app --reload
   ```
4. **Trigger scan**
   ```bash
   curl -X POST http://127.0.0.1:8000/scan/run
   ```
5. **CLI mode**
   ```bash
   python scripts/run_scan.py
   ```

## API Endpoints

- `GET /health` - health check
- `POST /scan/run` - run all enabled cloud scans, persist findings, generate reports
- `GET /findings?limit=100` - fetch latest findings

## Example Output

`POST /scan/run` returns:

```json
{
  "message": "scan_complete",
  "findings_created": 3,
  "report_files": [
    "reports/report_20260408_120000.json",
    "reports/report_20260408_120000.txt"
  ]
}
```

Readable report snippet:

```text
Cloud Vulnerability Report
Generated UTC: 2026-04-08T12:00:00
Total findings: 3
Severity summary:
- CRITICAL: 1
- HIGH: 2
```

## Real-world Use Case

Use this in a nightly security job to discover cloud drift (e.g., suddenly public buckets, permissive IAM trust policies, or exposed admin ports), then feed findings into ticketing/SIEM pipelines.

## Future Improvements

- Add support for AWS Config and Security Hub ingestion
- Add auto-remediation playbooks (optional approval gate)
- Add multi-account assume-role support
- Add Streamlit dashboard with trend analytics
- Add CVE mapping and exception lifecycle workflow
- Add Terraform checks for shift-left scanning

## Notes

- Requires AWS credentials with least-privilege read access.
- IAM/S3/EC2 APIs may require account-wide visibility permissions.
