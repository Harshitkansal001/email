# Architecture and data flow

```text
Browser (React + TypeScript)
  ├─ .eml bytes ───────────────┐
  └─ pasted raw headers ───────┤
                               ▼
FastAPI request size limits → stdlib email parser
                               │
                               ├─ selected header evidence
                               ├─ MIME metadata + bounded text + part provenance
                               ├─ URL and remote-image evidence + redacted path/query + IP scope
                               ├─ reported auth + Received route
                               ├─ recipient-aware export redaction
                               └─ deterministic rules
                                      │
                                      ▼
                         versioned JSON report
                                      │
                  browser renders or downloads JSON
```

## Components

- **Frontend:** React and TypeScript served by Vite in development. It sends either the original file bytes or raw header text, renders the response as escaped text, and creates a JSON download in the browser.
- **API:** FastAPI validates request shape and content type. A bounded ASGI middleware enforces byte limits even for chunked uploads. The API accepts loopback Host values and CORS origins for the local Vite server.
- **Parser and rules:** A low-allocation preflight rejects messages above 100,000 physical lines or 5,000 header-like lines before Python's standard-library email parser buffers them. The parser then walks MIME parts with count and depth limits. Attachments are inspected only for metadata. Rules emit findings with evidence references and a severity-derived priority.
- **Persistence:** None. There is no database, server-side upload storage, session, or account system. Request bytes and response objects exist transiently in process memory; the report remains in browser state until cleared or the page is closed.

## API contract

| Method and path | Input | Result |
| --- | --- | --- |
| `GET /api/health` | — | `{ "status": "ok" }` |
| `POST /api/v1/analyze/file` | raw bytes; `application/octet-stream` or `message/rfc822`; at most 5 MiB | `AnalysisResponse` |
| `POST /api/v1/analyze/headers` | JSON object with `raw_headers`, at most 64 KiB of text | `AnalysisResponse` |

Analysis responses use schema version `1.0` and include classification, rule priority, findings, evidence, authentication, routing, link and remote-image indicators, and limitations. Recipient local parts learned from `To`, `Delivered-To`, and `Received for <...>` fields are redacted in report strings, including VERP tokens; sender addresses remain visible for comparison. Failures use a stable `error.code` and a user-safe `error.message`.

## Interpretation and known limits

- `suspicious` means at least one medium or high severity rule matched. `inconclusive` means only low severity rules matched. `no_known_indicators` means no current rule matched. `risk_level` is not a calibrated score.
- SPF, DKIM, and DMARC are parsed from `Authentication-Results`; DKIM alignment uses passing per-signature domains when reported, and the header is not independently verified.
- Received values are displayed oldest-first by reversing header order. Any individual Received value can be forged. Candidate IPs are categorized by address scope; when a local GeoLite2 City database is installed, up to five public IPs receive approximate city-level location data without leaving the machine.
- The parser limits physical lines, header-like lines, selected headers, each displayed value, body text, MIME count/depth, URL count, and input size. Link extraction retains a sanitized path/query and identifies its MIME source part; remote images are listed separately. Links and images are never opened.
- Public IP registration data is optional and off by default. When enabled, up to five public IPs are sent to their IANA-bootstrapped regional RDAP registry over HTTPS; registry hosts are allowlisted and redirects are blocked. Registration details identify a network and may not identify the sender.
- Local geolocation uses `backend/data/GeoLite2-City.mmdb` or `MAXMIND_CITY_DB_PATH`. The database is not included in the repository and must be downloaded and kept current by the user.
- The classifier is not configured. Sender/body rules include display-name mismatch, urgency with a link, known click trackers, benign signals, and Date/Received/explicit Message-ID epoch comparisons.
- This MVP has no audit log or chain-of-custody guarantees. Do not expose its development server to a network.
