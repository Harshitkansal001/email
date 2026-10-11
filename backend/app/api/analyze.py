from fastapi import APIRouter, HTTPException, Request, Query
from starlette.concurrency import run_in_threadpool

from app.schemas.analysis import AnalysisResponse, HeaderAnalysisRequest
from app.security.validation import MAX_HEADER_TEXT_BYTES
from app.services.analyzer import analyze_message
from app.services.email_parser import MessageInputError

router = APIRouter(prefix="/api/v1/analyze", tags=["analysis"])


@router.post(
    "/file",
    response_model=AnalysisResponse,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}},
        }
    },
)
async def analyze_file(request: Request, enrich_ips: bool = Query(False)) -> AnalysisResponse:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type not in {"application/octet-stream", "message/rfc822"}:
        raise HTTPException(
            status_code=415,
            detail={"code": "unsupported_media_type", "message": "Send the .eml file as application/octet-stream or message/rfc822."},
        )
    raw = await request.body()
    try:
        return await run_in_threadpool(analyze_message, raw, "eml", enrich_ips)
    except MessageInputError as error:
        raise HTTPException(status_code=error.status_code, detail={"code": error.code, "message": error.message}) from None


@router.post("/headers", response_model=AnalysisResponse)
async def analyze_headers(body: HeaderAnalysisRequest) -> AnalysisResponse:
    try:
        raw = body.raw_headers.encode("utf-8")
        if len(raw) > MAX_HEADER_TEXT_BYTES:
            raise HTTPException(
                status_code=413,
                detail={"code": "headers_too_large", "message": "Header text exceeds the 64 KiB limit."},
            )
        return await run_in_threadpool(analyze_message, raw, "headers", body.enrich_ips)
    except MessageInputError as error:
        raise HTTPException(status_code=error.status_code, detail={"code": error.code, "message": error.message}) from None
