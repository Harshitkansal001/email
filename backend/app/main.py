from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.api.analyze import router as analyze_router
from app.security.validation import RequestBodyLimitMiddleware

app = FastAPI(title="Email Threat Forensics API", version="1.0.0")
app.include_router(analyze_router)


@app.get("/health", tags=["health"])
@app.get("/api/health", tags=["health"], include_in_schema=False)
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, __: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        {"error": {"code": "invalid_request", "message": "Request validation failed. Check the input format and limits."}},
        status_code=422,
    )


@app.exception_handler(HTTPException)
async def api_error(_: Request, error: HTTPException) -> JSONResponse:
    detail = error.detail if isinstance(error.detail, dict) else {}
    return JSONResponse(
        {"error": {
            "code": detail.get("code", "request_failed"),
            "message": detail.get("message", "The request could not be completed."),
        }},
        status_code=error.status_code,
        headers=error.headers,
    )


# Place Host validation outside body buffering so rejected hosts consume no upload memory.
app.add_middleware(RequestBodyLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])

_frontend_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if _frontend_dist.is_dir():
    app.mount("/", StaticFiles(directory=_frontend_dist, html=True), name="frontend")
