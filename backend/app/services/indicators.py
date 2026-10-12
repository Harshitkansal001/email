import ipaddress
import re
from urllib.parse import parse_qsl, urlencode, urlsplit

from app.schemas.analysis import Evidence, IpIndicator, RemoteImage, UrlIndicator
from app.services.email_parser import ParsedEmail

_URL = re.compile(r"https?://[^\s<>\"']{1,2048}", re.IGNORECASE)
_TRAILING_PUNCTUATION = ".,;:!?)]}"
_EMAIL = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)
_SENSITIVE_QUERY = re.compile(r"token|auth|secret|api.?key|password|email|recipient|contact|user|session|code|signature|(^|_)sig($|_)", re.IGNORECASE)
_OPAQUE_PATH = re.compile(r"^[A-Za-z0-9_-]{24,}$")
_REDIRECTORS = ("hubspotlinks.com",)
MAX_URLS = 100
_PRIVATE_NETWORKS = tuple(map(ipaddress.ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")))


def extract_indicators(
    parsed: ParsedEmail,
) -> tuple[list[UrlIndicator], list[RemoteImage], list[IpIndicator], list[Evidence], list[str]]:
    urls: list[UrlIndicator] = []
    remote_images: list[RemoteImage] = []
    ips: dict[str, set[str]] = {}
    evidence: list[Evidence] = []
    limitations: list[str] = []
    seen_urls: set[tuple[str, str, str, str]] = set()
    sources = [*((text, None, source_part) for source_part, text in parsed.body_parts),
               *((link.url, link, "text/html") for link in parsed.html_links)]
    url_limit_reached = False

    for source, html_link, source_part in sources:
        candidates = [(_candidate, None) for _candidate in _URL.findall(source)] if html_link is None else [(html_link.url, html_link)]
        for candidate, link in candidates:
            candidate = candidate.rstrip(_TRAILING_PUNCTUATION)
            if link is None and any(item.anchor_text and item.anchor_text.strip() == candidate for item in parsed.html_links):
                continue
            try:
                parts = urlsplit(candidate)
                host = parts.hostname
            except ValueError:
                continue
            if parts.scheme.lower() not in {"http", "https"} or not host:
                continue
            if len(urls) >= MAX_URLS:
                url_limit_reached = True
                break

            scheme, normalized_host = parts.scheme.lower(), host[:253].lower()
            path = _safe_path(parts.path or "/")
            query = _safe_query(parts.query)
            if (scheme, normalized_host, path, query or "") in seen_urls:
                continue
            ref = f"body:url:{len(urls) + 1}"
            seen_urls.add((scheme, normalized_host, path, query or ""))
            visible_host = _visible_host(link.anchor_text) if link else None
            indicator = UrlIndicator(evidence_ref=ref, host=normalized_host, scheme=scheme, path=path, query=query,
                                     redirector=any(normalized_host == item or normalized_host.endswith("." + item) for item in _REDIRECTORS),
                                     position=link.position if link else None,
                                     source_part=source_part,
                                     anchor_text=link.anchor_text if link else None,
                                     image_link=link.image_link if link else False,
                                     button_link=link.button_link if link else False,
                                     visible_text_mismatch=(
                                         visible_host != normalized_host
                                         if visible_host is not None
                                         else None
                                     ))
            urls.append(indicator)
            evidence.append(Evidence(
                evidence_ref=ref,
                evidence_refs=[ref],
                field="Link URL",
                value=f"{indicator.scheme}://{indicator.host}{indicator.path}{'?' + indicator.query if indicator.query else ''}",
                source_type="email_body",
            ))
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                continue
            ips.setdefault(str(address), set()).add(ref)
        if url_limit_reached:
            break

    for image in parsed.remote_images:
        try:
            parts = urlsplit(image.url.rstrip(_TRAILING_PUNCTUATION))
            host = parts.hostname
        except ValueError:
            continue
        if parts.scheme.lower() not in {"http", "https"} or not host:
            continue
        ref = f"body:remote-image:{len(remote_images) + 1}"
        indicator = RemoteImage(
            evidence_ref=ref,
            host=host[:253].lower(),
            scheme=parts.scheme.lower(),
            path=_safe_path(parts.path or "/"),
            query=_safe_query(parts.query),
            position=image.position,
        )
        remote_images.append(indicator)
        evidence.append(Evidence(
            evidence_ref=ref,
            evidence_refs=[ref],
            field="Remote image URL",
            value=f"{indicator.scheme}://{indicator.host}{indicator.path}{'?' + indicator.query if indicator.query else ''}",
            source_type="email_body",
        ))
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            continue
        ips.setdefault(str(address), set()).add(ref)

    if url_limit_reached:
        limitations.append("Only the first 100 links were analyzed.")

    ip_indicators = [
        IpIndicator(address=address, category=ip_category(ipaddress.ip_address(address)), evidence_refs=sorted(refs))
        for address, refs in ips.items()
    ]
    return urls, remote_images, ip_indicators, evidence, limitations


def _safe_path(path: str) -> str:
    return "/".join("[redacted]" if _EMAIL.search(piece) or _OPAQUE_PATH.fullmatch(piece) else _EMAIL.sub("[redacted]", piece)
                    for piece in path.split("/"))[:1024]


def _safe_query(query: str) -> str | None:
    if not query:
        return None
    try:
        pairs = parse_qsl(query[:8192], keep_blank_values=True, max_num_fields=100)
    except ValueError:
        return "[query omitted]"
    safe = [(key, "[redacted]" if _SENSITIVE_QUERY.search(key) or _EMAIL.search(value) or _OPAQUE_PATH.fullmatch(value) else value)
            for key, value in pairs]
    return urlencode(safe, doseq=True)[:2048]


def _visible_host(text: str | None) -> str | None:
    if not text:
        return None
    value = text.strip()
    try:
        parsed = urlsplit(value if "://" in value else "//" + value)
        host = parsed.hostname
    except ValueError:
        return None
    return host.lower() if host and ("." in host or "://" in value) else None


def ip_category(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_multicast:
        return "multicast"
    if address.is_unspecified:
        return "unspecified"
    if any(address.version == network.version and address in network for network in _PRIVATE_NETWORKS):
        return "private"
    if address.is_global:
        return "public"
    return "reserved"
