import re
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser

from app.schemas.analysis import AttachmentMetadata, Evidence

MAX_HEADER_COUNT = 200
MAX_MIME_DEPTH = 12
MAX_MIME_PARTS = 100
MAX_MESSAGE_HEADER_LINES = 5_000
MAX_MESSAGE_LINES = 100_000
MAX_BODY_TEXT_CHARS = 100_000
MAX_EVIDENCE_VALUE_CHARS = 2_048

_VISIBLE_HEADERS = {
    "from", "to", "cc", "delivered-to", "subject", "date", "reply-to", "return-path",
    "message-id", "received", "authentication-results", "dkim-signature",
}
_HEADER_LINE = re.compile(rb"(?m)^[!-9;-~]+:")


class MessageInputError(ValueError):
    def __init__(self, code: str, message: str, status_code: int = 422):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class _HtmlText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.links: list[HtmlLink] = []
        self.images: list[HtmlImage] = []
        self._active_link: dict | None = None
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() in {"script", "style"}:
            self._skip_depth += 1
        attributes = {name.lower(): value for name, value in attrs}
        if tag.lower() in {"a", "button"} and attributes.get("href"):
            classes = set((attributes.get("class") or "").lower().split())
            self._active_link = {
                "url": attributes["href"][:2_048], "text": [], "image": False,
                "button": tag.lower() == "button" or attributes.get("role") == "button" or bool(classes & {"btn", "button"}),
            }
        if tag.lower() == "img" and attributes.get("src"):
            if self._active_link is not None:
                self._active_link["image"] = True
            self.images.append(HtmlImage(url=attributes["src"][:2_048], position=len(self.images) + 1))

    def handle_endtag(self, tag):
        if tag.lower() in {"a", "button"} and self._active_link is not None:
            link = self._active_link
            self.links.append(HtmlLink(
                url=link["url"], position=len(self.links) + 1,
                anchor_text=" ".join(" ".join(link["text"]).split())[:256] or None,
                image_link=link["image"], button_link=link["button"],
            ))
            self._active_link = None
        if tag.lower() in {"script", "style"} and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data):
        if not self._skip_depth:
            self.text.append(data)
            if self._active_link is not None:
                self._active_link["text"].append(data)


@dataclass
class HtmlLink:
    url: str
    position: int
    anchor_text: str | None = None
    image_link: bool = False
    button_link: bool = False


@dataclass
class HtmlImage:
    url: str
    position: int


@dataclass
class ParsedEmail:
    input_type: str
    headers: list[tuple[str, str, str]]
    body_text: str
    body_parts: list[tuple[str, str]]
    html_links: list[HtmlLink]
    remote_images: list[HtmlImage]
    attachments: list[AttachmentMetadata]
    limitations: list[str]


def parse_email(raw: bytes, input_type: str) -> ParsedEmail:
    if not raw:
        raise MessageInputError("empty_input", "Provide a non-empty email message.")

    source = raw
    if input_type == "headers":
        source = _header_block(raw)

    # shortcut: global line/header-like caps bound stdlib parser buffering; raise after hostile-input profiling.
    line_count = source.count(b"\n") + source.count(b"\r") - source.count(b"\r\n")
    if line_count > MAX_MESSAGE_LINES:
        raise MessageInputError("message_too_many_lines", "The message exceeds the 100,000 line limit.")
    if sum(1 for _ in _HEADER_LINE.finditer(source)) > MAX_MESSAGE_HEADER_LINES:
        raise MessageInputError("message_too_many_headers", "The message exceeds the 5,000 header-like line limit.")

    try:
        message = BytesParser(policy=policy.default).parsebytes(source)
    except (ValueError, RecursionError, UnicodeError):
        raise MessageInputError("malformed_email", "The email could not be parsed safely.") from None

    raw_headers = message.items()
    if not raw_headers:
        raise MessageInputError("missing_headers", "No valid email headers were found.")
    if len(raw_headers) > MAX_HEADER_COUNT:
        raise MessageInputError("too_many_headers", "The message exceeds the header count limit.")

    limitations: list[str] = []
    if message.defects:
        limitations.append("The parser found malformed sections; some fields may be incomplete.")

    header_counts: dict[str, int] = {}
    headers: list[tuple[str, str, str]] = []
    for name, value in raw_headers:
        key = name.casefold()
        if key not in _VISIBLE_HEADERS:
            continue
        header_counts[key] = header_counts.get(key, 0) + 1
        text = str(value).strip()
        if len(text) > MAX_EVIDENCE_VALUE_CHARS:
            text = text[:MAX_EVIDENCE_VALUE_CHARS]
            limitations.append("One or more displayed header values were truncated.")
        headers.append((f"header:{name}:{header_counts[key]}", name, text))

    attachments: list[AttachmentMetadata] = []
    body_chunks: list[str] = []
    body_parts: list[tuple[str, str]] = []
    html_links: list[HtmlLink] = []
    remote_images: list[HtmlImage] = []
    body_length = 0
    part_count = 0
    stack = [(message, 0)]
    try:
        while stack:
            part, depth = stack.pop()
            part_count += 1
            if depth > MAX_MIME_DEPTH or part_count > MAX_MIME_PARTS:
                raise MessageInputError("mime_structure_limit", "The message exceeds the MIME structure limit.")
            if part.is_multipart():
                stack.extend((child, depth + 1) for child in reversed(list(part.iter_parts())))
                continue

            content_type = part.get_content_type().lower()
            disposition = part.get_content_disposition()
            filename = part.get_filename()
            if filename is not None or disposition == "attachment":
                payload = part.get_payload(decode=True)
                attachments.append(AttachmentMetadata(
                    filename=filename[:256] if filename else None,
                    content_type=content_type,
                    disposition=disposition,
                    size_bytes=len(payload) if payload is not None else None,
                ))
                continue

            if content_type not in {"text/plain", "text/html"}:
                continue
            payload = part.get_payload(decode=True)
            if payload is None:
                text = part.get_payload()
                if not isinstance(text, str):
                    continue
            else:
                charset = part.get_content_charset() or "ascii"
                try:
                    text = payload.decode(charset, errors="replace")
                except LookupError:
                    text = payload.decode("utf-8", errors="replace")

            remaining = MAX_BODY_TEXT_CHARS - body_length
            if remaining <= 0:
                limitations.append("Message body text was truncated at the analysis limit.")
                break
            text = text[:remaining]
            body_length += len(text)
            if content_type == "text/html":
                html = _HtmlText()
                html.feed(text)
                html.close()
                html_text = "\n".join(html.text)
                body_chunks.append(html_text)
                body_parts.append(("text/html", html_text))
                for link in html.links:
                    link.position += len(html_links)
                for image in html.images:
                    image.position += len(remote_images)
                html_links.extend(html.links)
                remote_images.extend(html.images)
            else:
                body_chunks.append(text)
                body_parts.append(("text/plain", text))
    except MessageInputError:
        raise
    except (RecursionError, ValueError, UnicodeError):
        raise MessageInputError("malformed_mime", "A message part could not be parsed safely.") from None

    if body_length >= MAX_BODY_TEXT_CHARS:
        limitations.append("Message body text was truncated at the analysis limit.")

    return ParsedEmail(
        input_type=input_type,
        headers=headers,
        body_text="\n".join(body_chunks),
        body_parts=body_parts,
        html_links=html_links,
        remote_images=remote_images,
        attachments=attachments,
        limitations=list(dict.fromkeys(limitations)),
    )


def _header_block(raw: bytes) -> bytes:
    block = re.split(rb"\r?\n\r?\n", raw, maxsplit=1)[0]
    if not any(b":" in line and not line.startswith((b" ", b"\t")) for line in block.splitlines()):
        raise MessageInputError("missing_headers", "Paste at least one valid email header.")
    return block + b"\r\n\r\n"
