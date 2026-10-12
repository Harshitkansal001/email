import ipaddress
import re
from email.utils import parseaddr

import tldextract

from app.schemas.analysis import AuthenticationResults, RouteHop, Routing
from app.services.email_parser import ParsedEmail

_AUTH_STATUS = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.IGNORECASE)
_BRACKETED_IP = re.compile(r"\[([0-9A-Fa-f:.%]+)\]")
_ROUTING_IP = re.compile(r"\b(?:from|by)\s+(\[[^\]]+\]|(?:\d{1,3}\.){3}\d{1,3})(?=\s|[;(]|$)", re.IGNORECASE)
_DKIM_DOMAIN = re.compile(r"(?:^|;)\s*d\s*=\s*([^;\s]+)", re.IGNORECASE)
_DKIM_RESULT = re.compile(r"(?:^|;)\s*dkim\s*=\s*([^\s;]+)([^;]*)", re.IGNORECASE)
_AUTH_HEADER_DOMAIN = re.compile(r"\bheader\.d\s*=\s*([^\s;]+)", re.IGNORECASE)
_EXTRACT_DOMAIN = tldextract.TLDExtract(suffix_list_urls=None, cache_dir=None)


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
    signature_domains = [
        normalized for _, name, value in parsed.headers if name.casefold() == "dkim-signature"
        for domain in _DKIM_DOMAIN.findall(re.sub(r"\s+", " ", value))
        if (normalized := _normalize_domain(domain))
    ]
    dkim_domains = sorted(set(signature_domains))
    dkim_results: list[tuple[str, str | None]] = []
    for _, value in headers:
        for status, properties in _DKIM_RESULT.findall(value):
            match = _AUTH_HEADER_DOMAIN.search(properties)
            dkim_results.append((status.casefold(), match.group(1) if match else None))
    passed_dkim_domains = {
        normalized for status, domain in dkim_results
        if status == "pass" and domain and (normalized := _normalize_domain(domain))
    }
    passed_dkim_domains.intersection_update(dkim_domains)
    unqualified_results = [status for status, domain in dkim_results if domain is None]
    if (
        not passed_dkim_domains
        and len(unqualified_results) == len(signature_domains)
        and unqualified_results
        and all(status == "pass" for status in unqualified_results)
    ):
        passed_dkim_domains.update(signature_domains)
    return_path_alignment = "unknown" if not from_domain or not return_path_domain else (
        "aligned" if _org_domain(from_domain) == _org_domain(return_path_domain) else "not_aligned"
    )
    spf_alignment = return_path_alignment if statuses["spf"] == "pass" else "not_aligned"
    dkim_alignment = _alignment(from_domain, sorted(passed_dkim_domains))
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
        alignment_note=None,
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


def _alignment(from_domain: str, domains: list[str]) -> str:
    if not from_domain or not domains:
        return "unknown"
    return "aligned" if any(_org_domain(from_domain) == _org_domain(domain) for domain in domains) else "not_aligned"


def _org_domain(domain: str) -> str:
    extracted = _EXTRACT_DOMAIN(domain)
    return extracted.top_domain_under_public_suffix or domain
