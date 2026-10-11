from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

AuthStatus = Literal[
    "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "unknown", "ambiguous"
]


class HeaderAnalysisRequest(BaseModel):
    raw_headers: str = Field(min_length=1, max_length=65_536)
    enrich_ips: bool = False


class Evidence(BaseModel):
    evidence_ref: str
    field: str
    value: str
    source_type: Literal["email_header", "email_body", "attachment_metadata"]


class Finding(BaseModel):
    rule_id: str
    title: str
    description: str
    severity: Literal["high", "medium", "low"]
    source_type: Literal["deterministic_rule"]
    evidence_refs: list[str]


class AttachmentMetadata(BaseModel):
    filename: str | None
    content_type: str
    disposition: str | None
    size_bytes: int | None


class AuthenticationResults(BaseModel):
    spf: AuthStatus = "unknown"
    dkim: AuthStatus = "unknown"
    dmarc: AuthStatus = "unknown"
    source: Literal["reported_by_message_header_not_verified"]
    evidence_refs: list[str]
    from_domain: str | None = None
    return_path_domain: str | None = None
    return_path_alignment: Literal["aligned", "not_aligned", "unknown"] = "unknown"
    dkim_domains: list[str] = Field(default_factory=list)
    spf_alignment: Literal["aligned", "not_aligned", "unknown"] = "unknown"
    dkim_alignment: Literal["aligned", "not_aligned", "unknown"] = "unknown"
    alignment_note: str = ""


class RouteHop(BaseModel):
    order: int
    evidence_ref: str
    value: str
    candidate_ips: list[str]


class Routing(BaseModel):
    status: Literal["available", "insufficient_evidence"]
    ordering: Literal["received_headers_reversed_oldest_first"]
    hops: list[RouteHop]
    note: str


class UrlIndicator(BaseModel):
    evidence_ref: str
    host: str
    scheme: Literal["http", "https"]
    path: str
    query: str | None = None
    redirector: bool = False


class IpIndicator(BaseModel):
    address: str
    category: Literal["public", "private", "loopback", "link_local", "multicast", "unspecified", "reserved"]
    evidence_refs: list[str]


class ClassifierOutput(BaseModel):
    status: Literal["not_configured"]
    label: None = None
    note: str


class EnrichmentOutput(BaseModel):
    status: Literal["not_requested", "not_configured", "complete", "partial", "unavailable"]
    ip_results: list[dict[str, str]] = Field(default_factory=list)
    note: str


class AnalysisResponse(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    analyzed_at: datetime
    input_type: Literal["eml", "headers"]
    classification: Literal["suspicious", "inconclusive", "no_known_indicators"]
    risk_level: Literal["high", "medium", "low", "undetermined"]
    findings: list[Finding]
    benign_indicators: list[str] = Field(default_factory=list)
    evidence: list[Evidence]
    attachments: list[AttachmentMetadata]
    url_indicators: list[UrlIndicator]
    ip_indicators: list[IpIndicator]
    authentication: AuthenticationResults
    routing: Routing
    classifier: ClassifierOutput
    enrichment: EnrichmentOutput
    limitations: list[str]
