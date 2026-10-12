import ipaddress
from datetime import datetime, timezone

from app.schemas.analysis import AnalysisResponse, Evidence, IpIndicator, UniqueTarget
from app.services.email_parser import parse_email
from app.services.header_trace import analyze_authentication, analyze_routing
from app.services.indicators import extract_indicators, ip_category
from app.services.ip_enrichment import enrich_public_ips
from app.services.ml_classifier import classify
from app.services.privacy import redact_recipient_identifiers, recipient_local_parts
from app.services.rules_engine import evaluate_rules


def analyze_message(raw: bytes, input_type: str, enrich_ips: bool = False, verify_rdns: bool = False) -> AnalysisResponse:
    parsed = parse_email(raw, input_type)
    recipient_locals = recipient_local_parts(parsed.headers)
    header_evidence: dict[tuple[str, str], Evidence] = {}
    for ref, name, value in parsed.headers:
        item = header_evidence.get((name.casefold(), value))
        if item:
            item.evidence_refs.append(ref)
        else:
            header_evidence[(name.casefold(), value)] = Evidence(
                evidence_ref=ref, evidence_refs=[ref], field=name, value=value, source_type="email_header",
            )
    evidence = list(header_evidence.values())
    evidence.extend(
        Evidence(
            evidence_ref=f"attachment:{index}",
            field="Attachment metadata",
            value=f"{item.filename or '(unnamed)'} · {item.content_type} · {item.size_bytes or 0} bytes",
            source_type="attachment_metadata",
        )
        for index, item in enumerate(parsed.attachments, start=1)
    )

    authentication = analyze_authentication(parsed)
    routing, route_ips = analyze_routing(parsed)
    urls, remote_images, ip_indicators, link_evidence, indicator_limitations = extract_indicators(parsed)
    targets: dict[tuple[str, str], list[str]] = {}
    for item in urls:
        targets.setdefault((item.host, item.path), []).append(item.evidence_ref)
    unique_targets = [UniqueTarget(host=host, path=path, evidence_refs=refs) for (host, path), refs in targets.items()]
    ip_refs = {item.address: set(item.evidence_refs) for item in ip_indicators}
    for address, ref in route_ips:
        ip_refs.setdefault(address, set()).add(ref)
    ip_indicators = [
        IpIndicator(
            address=address,
            category=ip_category(ipaddress.ip_address(address)),
            evidence_refs=sorted(refs),
        )
        for address, refs in ip_refs.items()
    ]
    evidence.extend(link_evidence)
    findings, classification, risk_level, benign_indicators = evaluate_rules(parsed, authentication, urls, evidence)

    limitations = [
        *parsed.limitations,
        *indicator_limitations,
        "No machine-learning classifier is configured; deterministic rules are not a probability.",
    ]
    if len([item for item in ip_indicators if item.category == "public"]) > 5 and enrich_ips:
        limitations.append("Only five public IP addresses are sent for registry lookup.")
    if input_type == "headers":
        limitations.append("Header-only input: body, links, and attachments were not available for analysis.")
    if not findings:
        limitations.append("No known rule indicators were found; this does not establish that the message is safe.")

    report = AnalysisResponse(
        analyzed_at=datetime.now(timezone.utc),
        input_type=input_type,
        classification=classification,
        risk_level=risk_level,
        findings=findings,
        benign_indicators=benign_indicators,
        evidence=evidence,
        attachments=parsed.attachments,
        url_indicators=urls,
        remote_images=remote_images,
        ip_indicators=ip_indicators,
        authentication=authentication,
        routing=routing,
        classifier=classify(parsed.body_text),
        enrichment=enrich_public_ips(ip_indicators, enrich_ips, verify_rdns),
        unique_targets=unique_targets,
        limitations=list(dict.fromkeys(limitations)),
    )
    return redact_recipient_identifiers(report, recipient_locals)
