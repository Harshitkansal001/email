import ipaddress
import re
from urllib.parse import parse_qsl, urlencode, urlsplit

from app.schemas.analysis import Evidence, IpIndicator, UrlIndicator
from app.services.email_parser import ParsedEmail

_URL = re.compile(r"https?://[^\s<>\"']{1,2048}", re.IGNORECASE)
_TRAILING_PUNCTUATION = ".,;:!?)]}"
_EMAIL = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)
_SENSITIVE_QUERY = re.compile(r"token|auth|secret|api.?key|password|email|recipient|contact|user|session|code|signature|(^|_)sig($|_)", re.IGNORECASE)
_OPAQUE_PATH = re.compile(r"^[A-Za-z0-9_-]{24,}$")
_REDIRECTORS = ("hubspotlinks.com",)
MAX_URLS = 100
_PRIVATE_NETWORKS = tuple(map(ipaddress.ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")))


def extract_indicators(parsed: ParsedEmail) -> tuple[list[UrlIndicator], list[IpIndicator], list[Evidence], list[str]]:
    urls: list[UrlIndicator] = []
    ips: dict[str, set[str]] = {}
    evidence: list[Evidence] = []
    limitations: list[str] = []
    seen_urls: set[tuple[str, str, str, str]] = set()
    sources = [(parsed.body_text, True), *((link, False) for link in parsed.html_links)]
    url_limit_reached = False

    for source, is_text in sources:
        candidates = _URL.findall(source) if is_text else [source]
        for candidate in candidates:
            candidate = candidate.rstrip(_TRAILING_PUNCTUATION)
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
            indicator = UrlIndicator(evidence_ref=ref, host=normalized_host, scheme=scheme, path=path, query=query,
                                     redirector=any(normalized_host == item or normalized_host.endswith("." + item) for item in _REDIRECTORS))
            urls.append(indicator)
            evidence.append(Evidence(
                evidence_ref=ref,
                field="Link destination host",
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

    if url_limit_reached:
        limitations.append("Only the first 100 links were analyzed.")

    ip_indicators = [
        IpIndicator(address=address, category=ip_category(ipaddress.ip_address(address)), evidence_refs=sorted(refs))
        for address, refs in ips.items()
    ]
    return urls, ip_indicators, evidence, limitations


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
