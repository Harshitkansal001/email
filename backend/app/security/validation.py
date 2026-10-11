from starlette.responses import JSONResponse

MAX_EML_BYTES = 5 * 1024 * 1024
MAX_HEADER_TEXT_BYTES = 64 * 1024
MAX_HEADER_REQUEST_BYTES = 320 * 1024

_REQUEST_LIMITS = {
    ("POST", "/api/v1/analyze/file"): MAX_EML_BYTES,
    ("POST", "/api/v1/analyze/headers"): MAX_HEADER_REQUEST_BYTES,
}


class RequestBodyLimitMiddleware:
    """Buffer only bounded analysis requests so chunked bodies cannot bypass limits."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = _REQUEST_LIMITS.get((scope["method"], scope["path"]))
        if limit is None:
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        encoding = headers.get(b"content-encoding", b"identity").lower()
        if encoding not in (b"", b"identity"):
            await self._error(scope, receive, send, 415, "unsupported_encoding", "Compressed request bodies are not supported.")
            return

        raw_length = headers.get(b"content-length")
        if raw_length:
            try:
                content_length = int(raw_length)
                if content_length < 0:
                    raise ValueError
                if content_length > limit:
                    await self._too_large(scope, receive, send)
                    return
            except ValueError:
                await self._error(scope, receive, send, 400, "invalid_content_length", "The request length is invalid.")
                return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > limit:
                await self._too_large(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        replayed = False

        async def replay_body():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay_body, send)

    async def _too_large(self, scope, receive, send):
        await self._error(scope, receive, send, 413, "payload_too_large", "The request exceeds the configured size limit.")

    async def _error(self, scope, receive, send, status_code, code, message):
        response = JSONResponse({"error": {"code": code, "message": message}}, status_code=status_code)
        await response(scope, receive, send)
