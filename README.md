# firewall-audit-backend

A FastAPI-based backend service for auditing firewall rule configurations. It parses rules from Cisco ACL and Palo Alto formats, detects dead/ineffective rules, and generates audit reports in JSON or CSV.

---

## Features

- **Rule parsing** — Supports Cisco extended ACL and Palo Alto `set rulebase` syntax; falls back to generic key=value format.
- **Dead rule detection** — Identifies parse errors, incomplete rules, redundant duplicates, shadowed rules, potentially unreferenced rules, and ineffective catch-all rules.
- **File upload** — Upload `.txt`, `.csv`, or `.json` firewall config files for automatic extraction and parsing.
- **CSV reports** — Download audit or dead-rules analysis results as CSV files.
- **Structured logging** — Rotating file logs with request, task, and analysis context; configurable via environment variables.

---

## Project Structure

```
main.py              # FastAPI app with CORS and global error handlers
config.py            # Pydantic-based settings (supports .env)
audit.py             # /api/v1/audit and /api/v1/audit/check-dead-rules routes
upload.py            # /api/v1/upload route
parser.py            # Rule parser (Cisco, Palo Alto, generic)
rule_checker.py      # DeadRuleDetector — 6-category dead rule analysis
file_handler.py      # Multi-format file content extractor
report_generator.py  # CSV report helpers
logger.py            # Logging configuration and specialised loggers
logs/                # Rotating daily log files (gitignored)
```

---

## Requirements

- Python 3.11+
- See [requirements.txt](requirements.txt)

```
fastapi>=0.115.0
uvicorn>=0.30.0
python-multipart>=0.0.7
python-dotenv>=1.0.0
pydantic>=2.9.0
pydantic-settings>=2.4.0
httpx2>=0.22.0
```

Install:

```bash
pip install -r requirements.txt
```

---

## Running the Server

```bash
uvicorn main:app --reload
```

The API is available at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.

---

## Deployment Setup

This repository is configured for deployment on Render using:

- `render.yaml` (Render Blueprint)
- `Procfile` (explicit web process command)
- `.env.example` (template for runtime environment variables)

### Production Start Command

```bash
uvicorn main:app --host 0.0.0.0 --port $PORT
```

Render injects the `PORT` environment variable automatically.

### Environment Variables

Set these in your Render service environment (or from Blueprint defaults):

| Variable | Suggested Value |
|----------|-----------------|
| `PYTHON_VERSION` | `3.11.9` |
| `LOG_LEVEL` | `INFO` |
| `DETAILED_LOGS` | `false` |
| `DISABLE_LOGGING` | `false` |
| `DEBUG` | `false` |
| `CORS_ORIGINS` | `["*"]` |

Optional metadata values used by root endpoint:

| Variable | Example |
|----------|---------|
| `APP_NAME` | `Firewall Audit Backend` |
| `APP_VERSION` | `1.0.0` |
| `USERNAME` | `ramyayarava76` |
| `EMAIL` | `ramyayarava76@gmail.com` |

---

## Render Setup

### Option A: Blueprint Deploy (recommended)

1. Push this repository to GitHub.
2. In Render, click **New +** -> **Blueprint**.
3. Connect your GitHub repository.
4. Render will detect `render.yaml` and create the `firewall-audit-backend` web service.
5. Click **Apply** to deploy.

### Option B: Manual Web Service

1. In Render, click **New +** -> **Web Service**.
2. Connect your repository and choose branch.
3. Use:
  - **Runtime:** Python
  - **Build Command:** `pip install -r requirements.txt`
  - **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Add environment variables from `.env.example`.
5. Deploy.

### Health Check

Render health check path:

```text
/health
```

You should see a JSON response like:

```json
{"status":"healthy"}
```

---

## API Endpoints

### Upload

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/api/v1/upload` | Returns upload usage info |
| `POST` | `/api/v1/upload` | Upload `.txt`/`.csv`/`.json` firewall config files |

**POST /api/v1/upload** — `multipart/form-data`, field name `files`.

### Audit

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/api/v1/audit` | Returns audit endpoint usage info |
| `POST` | `/api/v1/audit` | Parse and summarise firewall rules |
| `POST` | `/api/v1/audit/report` | Download audit results as CSV |
| `GET`  | `/api/v1/audit/check-dead-rules` | Returns dead-rules endpoint usage info |
| `POST` | `/api/v1/audit/check-dead-rules` | Detect dead rules in supplied rule list |
| `POST` | `/api/v1/audit/dead-rules-report` | Download dead-rules analysis as CSV |

**POST /api/v1/audit** request body:

```json
{
  "rules": ["access-list ACL1 extended permit tcp any host 10.0.0.1 eq 443"],
  "vendor": "cisco"
}
```

**POST /api/v1/audit/check-dead-rules** request body:

```json
{
  "rules": [
    "access-list ACL1 extended permit tcp any any",
    "access-list ACL1 extended permit tcp any host 10.0.0.1 eq 443"
  ],
  "vendor": "cisco"
}
```

---

## Dead Rule Categories

| Category | Description | Impact |
|----------|-------------|--------|
| Parse error | Rule could not be parsed | High |
| Incomplete rule | Missing `action`, `source`, `destination`, or `protocol` | Medium |
| Redundant rule | Exact duplicate of an earlier rule | Low |
| Shadowed by earlier rule | Unreachable due to a preceding broader rule (Cisco ACL) | High |
| Potentially unreferenced rule | Name pattern (`policy_`, `ref_`, `temp_`) suggests it should be called elsewhere | Medium |
| Ineffective catch-all rule | Matches `src=any dst=any` — may be a placeholder or security risk | Medium |

---

## Configuration

Settings are read from environment variables or a `.env` file:

| Variable | Default | Description |
|----------|---------|-------------|
| `CORS_ORIGINS` | `["*"]` | Allowed CORS origins |
| `DEBUG` | `false` | Enable debug mode |
| `LOG_LEVEL` | `INFO` | Logging level |
| `DETAILED_LOGS` | `false` | Enable verbose structured logging |
| `DISABLE_LOGGING` | `false` | Turn off all logging |

---

## Running Tests

```bash
pytest test_rule_checker.py test_rules.py test_api_dead_rules.py -v
```

All 11 tests should pass.

---

## Logs

Log files are written to the `logs/` directory:

- `logs/firewall_audit_YYYYMMDD.log` — General application log (10 MB rotation, 5 backups)
- `logs/firewall_audit_errors_YYYYMMDD.log` — Error-level log only
