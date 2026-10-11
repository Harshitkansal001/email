# Email Threat Forensics MVP

A local, single-user workbench for inspecting `.eml` messages or pasted headers. It reports explainable deterministic rule findings and shows the evidence behind them. It does not claim to identify a sender or determine that a message is safe.

## Run locally

Requirements: Python 3.11+ and Node.js 20.19+ or 22.12+.

In one terminal:

```sh
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

In another terminal:

```sh
cd frontend
npm ci
npm run dev
```

Open the URL printed by Vite. The frontend uses the local API at `127.0.0.1:8000`. To serve the built frontend from FastAPI, run `npm run build` first and start the backend; it serves `frontend/dist` when present.

## Analyze a message

Choose an `.eml` file (maximum 5 MiB) or paste raw headers (maximum 64 KiB). The API parses locally, returns a versioned JSON report, and the browser can download that report as JSON. Analysis state lives only in the page; no email database, upload directory, or account is used. Local IP geolocation is optional, and online registry lookups are separately opt-in.

### Optional local IP geolocation

To add offline location estimates, register for [MaxMind GeoLite2](https://www.maxmind.com/en/geolite-free-ip-geolocation-data), download and extract the GeoLite2 City `.mmdb` file to `backend/data/GeoLite2-City.mmdb`, then restart the backend. No MaxMind API key is needed at runtime and IP addresses are looked up locally. For another path, set `MAXMIND_CITY_DB_PATH` before starting the backend. The `.mmdb` file is ignored by Git; keep it updated under MaxMind's license terms.

Try the synthetic examples in `samples/`. They use reserved example domains and documentation IP ranges.

## API

- `GET /api/health` — local service status.
- `POST /api/v1/analyze/file` — raw `.eml` bytes with `Content-Type: application/octet-stream` or `message/rfc822`; maximum 5 MiB.
- `POST /api/v1/analyze/headers` — JSON `{ "raw_headers": "From: ..." }`; maximum 64 KiB of header text.
- `GET /docs` — interactive API schema.

Errors have the shape `{ "error": { "code": "...", "message": "..." } }`. Response schema version is `1.0`. See [docs/architecture.md](docs/architecture.md) for the analysis flow and limitations.

## Current analysis behavior

- Reports selected message headers, MIME attachment metadata, link hosts, authentication results as reported by the message, Received-header order, and candidate IP address scope.
- Applies deterministic rules for differing From/Reply-To domains, authentication failures, domain alignment, risky attachments, credential or urgency language with links, known click trackers, display-name mismatches, and timestamp skew.
- Shows evidence references for findings. Rule priority is severity-based and is not a probability.
- The classifier is not configured. If a GeoLite2 City database is installed, up to five public IPs are geolocated locally. Optional RDAP network lookups run only when selected; at most five public IPs are sent to their registries.
- A clean rule result means only that no known rule matched. Authentication and Received headers can be forged and are not independently verified.

## Limits and privacy

Requests are size-limited and parsed in memory. Before parsing, messages are capped at 100,000 physical lines and 5,000 header-like lines; displayed headers are capped at 200 and 2,048 characters per value; MIME traversal is limited to 100 parts and depth 12; extracted body text is capped at 100,000 characters and link indicators at 100. Attachments are never opened or returned. The service binds to loopback by default, accepts only loopback Host values, and does not log message content by design.

URL reports retain the host plus a sanitized path and query; email addresses, long opaque path tokens, and sensitive query values are redacted. Click-tracking URLs are not followed. Authentication is read from message headers and is not independently verified. Relaxed domain matching recognizes common public suffixes; uncommon endings may need manual review.

This MVP is not a malware sandbox, chain-of-custody system, email identity verifier, or production multi-user service. Do not expose the development server to a network.

## Project map

- `backend/app/api/` — analysis and health endpoints
- `backend/app/schemas/` — request and response contracts
- `backend/app/services/` — parser, evidence extraction, rules, and explicit unavailable integration states
- `backend/app/security/` — request body limits
- `backend/tests/` — API, parser, and limit checks
- `frontend/src/api/` — typed API client and response types
- `frontend/src/App.tsx` — upload/header workflow and report
- `samples/` — synthetic messages for manual review
- `docs/` — architecture and data flow

## Checks

```sh
cd backend
python -m pip install -r requirements-dev.txt
python -m pytest
cd ../frontend
npm run build
```
