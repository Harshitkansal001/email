import ipaddress
import re
from email.utils import parseaddr

from app.schemas.analysis import AuthenticationResults, RouteHop, Routing
from app.services.email_parser import ParsedEmail

_AUTH_STATUS = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.IGNORECASE)
_BRACKETED_IP = re.compile(r"\[([0-9A-Fa-f:.%]+)\]")
_ROUTING_IP = re.compile(r"\b(?:from|by)\s+(\[[^\]]+\]|(?:\d{1,3}\.){3}\d{1,3})(?=\s|[;(]|$)", re.IGNORECASE)
_AUTH_DOMAIN = re.compile(r"\b(smtp\.mailfrom|header\.from|header\.d)\s*=\s*<?([^\s>;]+)>?", re.IGNORECASE)
_DKIM_DOMAIN = re.compile(r"(?:^|;)\s*d\s*=\s*([^;\s]+)", re.IGNORECASE)


def analyze_authentication(parsed: ParsedEmail) -> AuthenticationResults:
    headers = [(ref, value) for ref, name, value in parsed.headers if name.casefold() == "authentication-results"]
    found: dict[str, set[str]] = {"spf": set(), "dkim": set(), "dmarc": set()}
    for _, value in headers:
        for mechanism, status in _AUTH_STATUS.findall(value):
            found[mechanism.lower()].add(status.lower())

    statuses = {}
    for mechanism, values in found.items():
        statuses[mechanism] = next(iter(values)) if len(values) == 1 else "ambiguous" if values else "unknown"

    from_address = _header_value(parsed, "from")
    from_domain = _domain(from_address)
    return_path_domain = _domain(_header_value(parsed, "return-path"))
    auth_domains = {key.lower(): [] for key in ("smtp.mailfrom", "header.d")}
    for _, value in headers:
        for key, domain in _AUTH_DOMAIN.findall(value):
            normalized = _normalize_domain(domain.rsplit("@", 1)[-1] if key.lower() == "smtp.mailfrom" else domain)
            if normalized and key.lower() in auth_domains:
                auth_domains[key.lower()].append(normalized)
    dkim_domains = list(dict.fromkeys(auth_domains["header.d"] + [
        normalized for ref, _, value in parsed.headers if ref.startswith("header:dkim-signature:")
        for domain in _DKIM_DOMAIN.findall(value) if (normalized := _normalize_domain(domain))
    ]))
    spf_domains = auth_domains["smtp.mailfrom"] or ([return_path_domain] if return_path_domain else [])
    return_path_alignment = "unknown" if not from_domain or not return_path_domain else (
        "aligned" if _org_domain(from_domain) == _org_domain(return_path_domain) else "not_aligned"
    )
    spf_alignment = _alignment(statuses["spf"], from_domain, spf_domains)
    dkim_alignment = _alignment(statuses["dkim"], from_domain, dkim_domains)
    return AuthenticationResults(
        **statuses,
        source="reported_by_message_header_not_verified",
        evidence_refs=[ref for ref, _ in headers],
        from_domain=from_domain or None,
        return_path_domain=return_path_domain or None,
        return_path_alignment=return_path_alignment,
        dkim_domains=dkim_domains,
        spf_alignment=spf_alignment,
        dkim_alignment=dkim_alignment,
        alignment_note="Common public suffixes are recognized for relaxed alignment. Less common suffixes may need manual review.",
    )


def analyze_routing(parsed: ParsedEmail) -> tuple[Routing, list[tuple[str, str]]]:
    received = [(ref, value) for ref, name, value in parsed.headers if name.casefold() == "received"]
    hops: list[RouteHop] = []
    candidate_ips: list[tuple[str, str]] = []

    for order, (ref, value) in enumerate(reversed(received), start=1):
        addresses: list[str] = []
        tokens = [*_BRACKETED_IP.findall(value), *_ROUTING_IP.findall(value)]
        for token in tokens:
            try:
                address = ipaddress.ip_address(token.strip("[]").split("%", 1)[0])
            except ValueError:
                continue
            normalized = str(address)
            if normalized not in addresses:
                addresses.append(normalized)
                candidate_ips.append((normalized, ref))
        hops.append(RouteHop(order=order, evidence_ref=ref, value=value, candidate_ips=addresses))

    return Routing(
        status="available" if hops else "insufficient_evidence",
        ordering="received_headers_reversed_oldest_first",
        hops=hops,
        note=(
            "Received values are shown in reverse header order as an oldest-first view. "
            "The values may be forged and are not independently verified."
            if hops else "No Received headers were available; the route cannot be reconstructed."
        ),
    ), candidate_ips


def _header_value(parsed: ParsedEmail, name: str) -> str:
    return next((value for _, header, value in parsed.headers if header.casefold() == name), "")


def _domain(value: str) -> str:
    address = parseaddr(value)[1]
    return _normalize_domain(address.rsplit("@", 1)[-1]) if "@" in address else ""


def _normalize_domain(value: str) -> str:
    value = value.strip().strip("<>").rstrip(".").lower()
    try:
        return value.encode("idna").decode("ascii") if value else ""
    except UnicodeError:
        return ""


def _alignment(status: str, from_domain: str, domains: list[str]) -> str:
    if status not in {"pass", "fail", "softfail", "permerror", "neutral", "none"} or not from_domain:
        return "unknown"
    if status != "pass" or not domains:
        return "unknown"
    return "aligned" if any(_org_domain(from_domain) == _org_domain(domain) for domain in domains) else "not_aligned"


_MULTI_LABEL_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "com.br", "com.cn", "co.jp", "co.in", "com.sg", "com.mx", "com.tr", "com.tw", "com.hk", "com.ar", "com.co", "co.za", "com.my"}


def _org_domain(domain: str) -> str:
    # shortcut: common multi-label suffixes only; use maintained public-suffix data for uncommon suffixes.
    labels = domain.split(".")
    suffix = ".".join(labels[-2:])
    count = 3 if suffix in _MULTI_LABEL_SUFFIXES else 2
    return ".".join(labels[-count:]) if len(labels) >= count else domain
