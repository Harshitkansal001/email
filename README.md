# Email Threat Forensics MVP

Local, single-user email analysis workbench. This starter runs a React frontend and FastAPI backend; analysis features are not implemented yet.

## Requirements

- Python 3.11 or newer
- Node.js 20 or newer

## Run locally

In one terminal:

```sh
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

In another terminal:

```sh
cd frontend
npm ci
npm run dev
```

Open the URL printed by Vite. The starter page checks `GET /api/health` through Vite's development proxy.

## Structure

- `backend/app/api/` — FastAPI routes
- `backend/app/schemas/` — Pydantic request and response models
- `backend/app/services/` — parsing, indicators, rules, classifier, routing, enrichment, and reports
- `backend/app/security/` — request validation and transient-data cleanup
- `frontend/src/api/` — frontend API calls
- `frontend/src/components/` — reusable interface components
- `frontend/src/pages/` — application views
- `samples/` — synthetic or licensed test messages
- `docs/` — architecture and API documentation

The MVP has no database or user accounts. Keep email content transient, avoid logging message contents, and bind local services to loopback. Before analysis features are added, decide upload limits, cleanup semantics, classifier, enrichment source, and risk labels.
