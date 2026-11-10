# 🛡️ PrivacyGuard — Explainable Application Privacy and Permission Analyzer
**Problem Statement: PS02 — Cybersecurity / Application Privacy / Explainable Security**

[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.15-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI%200.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Frontend-Streamlit%201.35+-FF4B4B.svg)](https://streamlit.io/)
[![Security](https://img.shields.io/badge/Security-Argon2id%20%7C%20DefusedXML%20%7C%20Rotating%20JWT-00D4FF.svg)]()
[![Tests](https://img.shields.io/badge/Test%20Suite-81%20Passed%20(100%25)-green.svg)]()

PrivacyGuard is an explainable cybersecurity auditing platform that inspects Android application permissions, securely parses `AndroidManifest.xml` files, and cross-examines requested device capabilities against declared privacy policies. It provides objective, evidence-grounded risk assessments without falsely labeling applications as malicious.

---

## 📑 Table of Contents
1. [Key Features & Explainable Security Principles](#-key-features--explainable-security-principles)
2. [System Architecture](#-system-architecture)
3. [Prerequisites & Environment Setup](#-prerequisites--environment-setup)
4. [Database Configuration & Migrations](#-database-configuration--migrations)
5. [Database Backup & Restore Instructions](#-database-backup--restore-instructions)
6. [Running PrivacyGuard (Development Mode)](#-running-privacyguard-development-mode)
7. [Production Deployment Guide](#-production-deployment-guide)
8. [Health-Check, Logging & System Diagnostics](#-health-check-logging--system-diagnostics)
9. [Synthetic Demo Data Overview](#-synthetic-demo-data-overview)
10. [Hackathon Demonstration Flow (Step-by-Step)](#-hackathon-demonstration-flow-step-by-step)
11. [Security Hardening & Best Practices](#-security-hardening--best-practices)

---

## 🌟 Key Features & Explainable Security Principles

1. **Non-Presumptive Explainability Engine:**
   - Adheres strictly to cybersecurity forensic standards: declaring a permission in the manifest does **not** prove that the capability was granted at runtime or actively exploited.
   - Explains what information may be accessed, what device hardware is gated, and why the capability is sensitive.
   - Unknown/unsupported vendor permissions are strictly marked as `UNKNOWN` without fabricated explanations.

2. **Hardened XML Parser (`defusedxml`):**
   - Neutralizes XML entity expansion attacks (Billion Laughs), quadratic blowup, and External Entity (XXE) injection.
   - Enforces a 5 MB upload limit, checks for binary AXML rejection, and sanitizes filenames against path traversal.

3. **Evidence-Linked Privacy Policy Grounding:**
   - Detects 14 core privacy domains (Camera, Microphone, Precise/Coarse Location, Contacts, Storage, Third-Party Sharing, etc.).
   - Preserves exact source text excerpts with paragraph references and character offsets.
   - Flags policy contradictions (e.g., manifest requests `READ_SMS` while policy claims *"We never collect SMS"*).

4. **Synchronized Dual-Tier Authentication:**
   - **FastAPI Authority:** FastAPI is the sole source of truth for passwords, JWT issuance, and refresh tokens. Streamlit never authenticates users independently.
   - **Argon2id Hashing:** Industry-standard password hashing with cryptographically random per-user salt.
   - **Rotating Refresh Tokens:** Long-lived refresh tokens rotate on every refresh; raw tokens are never persisted in the database (only SHA-256 hashes in `user_sessions`). Replaying a revoked token triggers an immediate account-wide session revocation.
   - **Server-Side Session State:** Tokens are stored exclusively in Streamlit's server-side session memory (`st.session_state`); zero credentials in URLs or browser storage.

5. **Multi-Format Evidence-Linked Reports:**
   - Download audit findings in **PDF** (tamper-evident ReportLab document with executive summaries, findings tables, and methodology limitations), **JSON**, or **CSV**.

---

## 🏗️ System Architecture

```mermaid
flowchart TD
    subgraph Client ["Client Browser"]
        UI["Streamlit Frontend (Port 8501)"]
    end

    subgraph BackendGateway ["FastAPI Gateway (Port 8000)"]
        AUTH_ROUTER["/api/v1/auth\n(Argon2id, JWT, Rotation)"]
        ANALYSIS_ROUTER["/api/v1/analysis\n(DefusedXML & Uploads)"]
        ADMIN_ROUTER["/api/v1/admin\n(RBAC & System Telemetry)"]
        HEALTH["/api/v1/health\n(Deep Probes: DB, KB, Storage)"]
    end

    subgraph CoreEngine ["Core Cybersecurity Engine"]
        PARSER["DefusedXML Parser\n(XPath Traceability & Size Limits)"]
        KB["Curated Permission KB\n(Android 6 to 14 API Context)"]
        POLICY_MOD["Policy Analyzer\n(14 Domains & Evidence Offsets)"]
        EXPLAIN["Explainability Engine\n(Non-Presumptive Rationale)"]
        REPORT_GEN["ReportLab PDF Engine\n(Evidence-Linked Reports)"]
    end

    subgraph Storage ["Persistent Storage"]
        DB[(Database Engine\nPostgreSQL or SQLite)]
        REPORTS_DIR[("Report Artifacts Directory\n./reports/")]
    end

    UI -->|"HTTP + Bearer JWT"| BackendGateway
    ANALYSIS_ROUTER --> PARSER
    PARSER --> KB
    ANALYSIS_ROUTER --> POLICY_MOD
    POLICY_MOD --> EXPLAIN
    EXPLAIN --> REPORT_GEN
    BackendGateway --> DB
    REPORT_GEN --> REPORTS_DIR
```

---

## 📦 Prerequisites & Environment Setup

### 1. Requirements
- Python 3.10+ (tested on Python 3.10, 3.11, 3.12, and 3.15)
- Git
- SQLite (default for development) or PostgreSQL 14+ (for production)

### 2. Installation
Clone the repository and install the dependencies:

```bash
git clone https://github.com/organization/explainable-privacy-analyzer.git
cd explainable-privacy-analyzer

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Environment Configuration
Copy the configuration template:

```bash
cp .env.example .env
```

Review and adjust variables in `.env`:

| Variable | Default (Dev) | Description |
| :--- | :--- | :--- |
| `PROJECT_NAME` | `Explainable Application Privacy and Permission Analyzer` | System name |
| `ENV` | `development` | Environment mode (`development` / `production`) |
| `SECRET_KEY` | *(sample key)* | Cryptographic HMAC secret for JWT signing. **Change in production!** |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | Short-lived access token lifespan |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifespan before rotation |
| `DATABASE_URL` | `sqlite:///./privacy_analyzer.db` | Database connection URI (SQLite or PostgreSQL) |
| `MAX_UPLOAD_SIZE_MB` | `5` | Maximum upload size for manifest files |
| `MAX_POLICY_LENGTH` | `1000000` | Maximum privacy policy character count |
| `DEFAULT_ADMIN_EMAIL` | `admin@privacyanalyzer.local` | Initial admin account email |
| `DEFAULT_ADMIN_PASSWORD` | *(custom password)* | Initial admin account password |
| `BACKEND_API_URL` | `http://127.0.0.1:8000/api/v1` | Backend URL used by Streamlit frontend |

---

## 🗄️ Database Configuration & Migrations

PrivacyGuard supports both **SQLite** (local development) and **PostgreSQL** (production deployment) using SQLAlchemy and Alembic.

### 1. SQLite (Development Default)
No separate database server required. SQLite database is created automatically at `./privacy_analyzer.db`:
```bash
DATABASE_URL="sqlite:///./privacy_analyzer.db"
```

### 2. PostgreSQL (Production Setup)
1. Create a dedicated PostgreSQL database and user:
   ```sql
   CREATE DATABASE privacyguard_db;
   CREATE USER privacyguard_user WITH ENCRYPTED PASSWORD 'StrongProductionPassword';
   GRANT ALL PRIVILEGES ON DATABASE privacyguard_db TO privacyguard_user;
   ```
2. Update `DATABASE_URL` in `.env`:
   ```bash
   DATABASE_URL="postgresql://privacyguard_user:StrongProductionPassword@localhost:5432/privacyguard_db"
   ```

### 3. Running Migrations
Apply Alembic migrations to configure all 8 database tables:
```bash
alembic upgrade head
```

To verify the migration status:
```bash
alembic current
```

---

## 💾 Database Backup & Restore Instructions

### 1. SQLite Backup & Recovery
- **Safe Online Backup (no downtime):**
  ```bash
  # Using SQLite CLI:
  sqlite3 privacy_analyzer.db ".backup 'privacy_analyzer_backup_$(date +%Y%m%d_%H%M%S).db'"
  ```
- **Automated Python Script:**
  ```bash
  python -c "import sqlite3, shutil, datetime; con=sqlite3.connect('privacy_analyzer.db'); bck=sqlite3.connect(f'reports/backup_{datetime.date.today()}.db'); con.backup(bck); bck.close(); con.close(); print('Backup complete.')"
  ```
- **Restoration:**
  ```bash
  cp reports/backup_YYYY-MM-DD.db privacy_analyzer.db
  ```

### 2. PostgreSQL Backup & Recovery
- **Create Compressed Backup:**
  ```bash
  pg_dump -h localhost -U privacyguard_user -F c -b -v -f "privacyguard_backup_$(date +%Y%m%d).dump" privacyguard_db
  ```
- **Restore from Backup:**
  ```bash
  pg_restore -h localhost -U privacyguard_user -d privacyguard_db -v "privacyguard_backup_YYYYMMDD.dump"
  ```

---

## 🚀 Running PrivacyGuard (Development Mode)

Start both services concurrently in two terminal tabs:

### Terminal 1: FastAPI Backend
```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
- Interactive Swagger UI: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- ReDoc Documentation: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- Health Probe: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

### Terminal 2: Streamlit Frontend
```bash
streamlit run frontend/app.py --server.port 8501
```
- Web Application: [http://localhost:8501](http://localhost:8501)

---

## 🌐 Production Deployment Guide

### Architecture Best Practice
In production:
1. Run **FastAPI** behind Gunicorn with Uvicorn workers.
2. Run **Streamlit** on an internal port.
3. Terminate SSL/TLS at **Nginx** or **Caddy** reverse proxy.
4. Connect to **PostgreSQL**.

### 1. Production `.env` Settings
```bash
ENV="production"
SECRET_KEY="<generate-with-secrets.token_urlsafe(64)>"
DATABASE_URL="postgresql://privacyguard_user:SecretPass@127.0.0.1:5432/privacyguard_db"
BACKEND_API_URL="https://api.privacyguard.example.com/api/v1"
CORS_ORIGINS="https://privacyguard.example.com"
```

### 2. Gunicorn + Uvicorn Service (FastAPI)
Run backend with multiple worker processes:
```bash
gunicorn backend.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 127.0.0.1:8000 --access-logfile - --error-logfile -
```

### 3. Streamlit Production Service
```bash
streamlit run frontend/app.py \
    --server.port 8501 \
    --server.address 127.0.0.1 \
    --server.headless true \
    --server.enableCORS false \
    --server.enableXsrfProtection true
```

### 4. Sample Nginx Reverse Proxy Configuration
```nginx
# FastAPI API Gateway
server {
    listen 443 ssl http2;
    server_name api.privacyguard.example.com;

    ssl_certificate /etc/letsencrypt/live/privacyguard.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/privacyguard.example.com/privkey.pem;

    client_max_body_size 10M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Streamlit UI
server {
    listen 443 ssl http2;
    server_name privacyguard.example.com;

    ssl_certificate /etc/letsencrypt/live/privacyguard.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/privacyguard.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8501;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support for Streamlit
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }
}
```

---

## 🔍 Health-Check, Logging & System Diagnostics

### 1. Health-Check Endpoint
FastAPI provides deep health probes at `GET /health` and `GET /api/v1/health`.
Sample JSON response:
```json
{
  "status": "healthy",
  "environment": "production",
  "version": "1.0.0",
  "timestamp": "2026-11-10T06:30:00Z",
  "components": {
    "database": {
      "status": "connected",
      "engine": "postgresql"
    },
    "knowledge_base": {
      "status": "loaded",
      "entries": 36
    },
    "report_storage": {
      "status": "writable",
      "path": "/var/www/privacyguard/reports"
    }
  }
}
```
If any component fails (e.g. database unreachable), the endpoint returns `503 Service Unavailable`.

### 2. Structured Application Logging
Logs follow an ISO-8601 standardized format:
```text
2026-11-10T06:25:36Z [INFO] [privacyguard.backend] Starting Explainable Application Privacy and Permission Analyzer in [PRODUCTION] mode
2026-11-10T06:25:36Z [INFO] [privacyguard.backend] Verifying database schema...
2026-11-10T06:25:36Z [INFO] [privacyguard.backend] Knowledge Base active with 36 verified Android permissions.
```

---

## 🧪 Synthetic Demo Data Overview

Synthetic targets are located in `data/synthetic_demo/` and are strictly isolated from real user evaluations:

| Demo Target | Files | Scenario Characteristics |
| :--- | :--- | :--- |
| **QuickScan Document Scanner** | `sample_manifest.xml`, `sample_privacy_policy.txt` | Photo scanner requesting Camera, Storage, and uncataloged vendor telemetry `com.synthetic.vendor.custom.DIAGNOSTIC_TELEMETRY` (triggers strict `UNKNOWN` explainability). |
| **Synthetic Minimal Calculator** | `calculator/synthetic_calculator_manifest.xml`, `calculator/synthetic_calculator_policy.txt` | Minimal utility requesting only `VIBRATE` (haptics) and `INTERNET` (ads). Demonstrates verified safe risk profile. |
| **RoadMaster Navigation** | `navigation/synthetic_navigation_manifest.xml`, `navigation/synthetic_navigation_policy.txt` | Location-intensive app with `ACCESS_FINE_LOCATION`, `ACCESS_BACKGROUND_LOCATION`, and `FOREGROUND_SERVICE`. |
| **Pulse Chat & Messaging** | `messaging/synthetic_messaging_manifest.xml`, `messaging/synthetic_messaging_policy.txt` | Multi-capability suite with Camera, Audio recording, and Contacts. |

---

## 🎬 Hackathon Demonstration Flow (Step-by-Step)

Follow this exact 15-step sequence during evaluator demonstrations:

1. **Open PrivacyGuard:** Navigate to [http://localhost:8501](http://localhost:8501).
2. **Register an account:**
   - Click *Create New Analyst Account*.
   - Enter your name (e.g., `Evaluator Jane`), email (`evaluator@hackathon.org`), and a compliant password (e.g., `AuditPass2026!`).
   - Accept terms and click *Complete Registration*.
3. **Log in:**
   - Enter your email and password.
   - Click *Sign In to Portal*.
4. **Open dashboard:**
   - View initial zero-state telemetry metrics (Total Analyses, Permissions, Risk Distribution).
5. **Upload sample AndroidManifest.xml:**
   - Click *New Analysis* in sidebar.
   - In the *Upload Files* tab, upload [`data/synthetic_demo/sample_manifest.xml`](data/synthetic_demo/sample_manifest.xml).
6. **Enter application purpose:**
   - Enter: `"Scan receipts and documents using device camera, save images to device, and backup to cloud"`.
7. **Add optional privacy policy:**
   - Paste the contents of [`data/synthetic_demo/sample_privacy_policy.txt`](data/synthetic_demo/sample_privacy_policy.txt).
8. **Run analysis:**
   - Click *Analyze Uploaded Manifest*.
9. **View permission explanations:**
   - Inspect the explainable risk breakdown: `android.permission.CAMERA` (Dangerous, High Sensitivity) with verified platform context.
10. **Review unknown permissions:**
    - Observe `com.synthetic.vendor.custom.DIAGNOSTIC_TELEMETRY` cleanly categorized as `UNKNOWN` with non-presumptive warnings and zero fabricated explanations.
11. **Review privacy policy excerpts:**
    - Examine extracted policy passages with exact character offsets for Camera usage and Document Storage.
12. **Review purpose comparison questions:**
    - Review the explainability question: *Why does the document scanner request camera access? (Potentially Expected for scanning)*.
13. **Download PDF report:**
    - In the *Download Evidence-Linked Analysis Reports* bar, click **📄 Download PDF Report**.
    - Open the downloaded ReportLab PDF and view the cover page, risk gauges, findings table, and limitations disclosures.
14. **Open analysis history:**
    - Click *History* in the sidebar to review the persisted audit record.
15. **Log out:**
    - Click *Sign Out* in the sidebar. Verify that session tokens are revoked and you are redirected to the sign-in portal.

---

## 🔒 Security Hardening & Best Practices

- **Zero Client Trust:** Streamlit client forms never dictate user identity or access rights.
- **Argon2id Memory-Hard Hashing:** Resists GPU and ASIC brute-force attacks.
- **XXE & Entity Expansion Defense:** `defusedxml` protects against entity expansion and DTD attacks.
- **File & Storage Safety:** Filenames are stripped of path traversal patterns; uploaded payloads are inspected in memory without shell execution.
- **Git Hygiene:** `.gitignore` excludes `.env`, `*.db`, `reports/*.pdf`, `reports/*.json`, and `uploads/*`.

---

## 🧪 Running Automated Tests

Run the complete test suite to verify full integration:

```bash
pytest -v
```

Expected result:
```text
============================= 81 passed in 12.54s =============================
```

---

## 📄 License
This project is licensed under the Apache 2.0 License. Developed for Problem Statement **PS02: Explainable Application Privacy and Permission Analyzer**.
