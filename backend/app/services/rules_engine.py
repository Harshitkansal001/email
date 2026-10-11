import ipaddress
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime, parseaddr

from app.schemas.analysis import AuthenticationResults, Evidence, Finding
from app.services.email_parser import ParsedEmail

_CREDENTIAL_LANGUAGE = re.compile(
    r"\b(?:password|passcode|sign[ -]?in|log[ -]?in|verify (?:your )?(?:account|identity)|"
    r"account (?:will be |is )?(?:suspended|locked)|credentials)\b",
    re.IGNORECASE,
)
_RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".hta", ".lnk", ".iso", ".xlsm", ".docm"}
_URGENCY = re.compile(r"\b(?:urgent|immediately|act now|final notice|within \d+ hours?|account (?:will be )?suspended|last chance)\b", re.IGNORECASE)
_EPOCH_TOKEN = re.compile(r"(?:^|\D)(1[5-9]\d{8}|2\d{9})(?:\D|$)")
_DKIM_TIME = re.compile(r"(?:^|;)\s*t\s*=\s*(\d+)\b", re.IGNORECASE)
_KNOWN_MAIL_HOSTS = ("google.com", "googlemail.com", "outlook.com", "protection.outlook.com", "amazonses.com", "hubspot.com", "hubspotlinks.com", "mailchimp.com")


def evaluate_rules(
    parsed: ParsedEmail,
    authentication: AuthenticationResults,
    url_indicators,
    evidence: list[Evidence],
) -> tuple[list[Finding], str, str, list[str]]:
    findings: list[Finding] = []
    evidence_by_ref = {item.evidence_ref: item for item in evidence}
    headers: dict[str, list[tuple[str, str]]] = {}
    for ref, name, value in parsed.headers:
        headers.setdefault(name.casefold(), []).append((ref, value))

    sender = _address(headers.get("from", []))
    display_name = parseaddr(headers.get("from", [("", "")])[0][1])[0]
    reply_to = _address(headers.get("reply-to", []))
    if sender and reply_to and _domain(sender) and _domain(reply_to) and _domain(sender) != _domain(reply_to):
        refs = [headers["from"][0][0], headers["reply-to"][0][0]]
        findings.append(_finding(
            "reply_to_domain_mismatch", "Reply address uses a different domain", "The Reply-To domain differs from the From domain.", "medium", refs,
        ))

    embedded_emails = _EMAIL_IN_TEXT.findall(display_name)
    if embedded_emails and any(_domain(email) != _domain(sender) for email in embedded_emails) and sender:
        findings.append(_finding("display_name_address_mismatch", "Display name names a different email address",
                                 "The sender name contains an email address that does not match the actual From address.", "medium",
                                 [headers["from"][0][0]]))

    auth_fail_refs = authentication.evidence_refs if any(
        getattr(authentication, name) in {"fail", "softfail", "permerror"}
        for name in ("spf", "dkim", "dmarc")
    ) else []
    if auth_fail_refs:
        findings.append(_finding(
            "reported_authentication_failure", "Authentication failure reported", "An Authentication-Results header reports a failure. The header was not independently verified.", "medium", auth_fail_refs,
        ))

    for index, attachment in enumerate(parsed.attachments, start=1):
        filename = attachment.filename or ""
        extension = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if extension in _RISKY_EXTENSIONS:
            ref = f"attachment:{index}"
            findings.append(_finding(
                "risky_attachment_extension", "Potentially risky attachment type", "The attachment filename uses an extension commonly associated with executable or macro-enabled content. The attachment was not opened.", "high", [ref],
            ))

    body_has_credential_language = bool(_CREDENTIAL_LANGUAGE.search(parsed.body_text))
    if body_has_credential_language and url_indicators:
        ref = "body:credential_language"
        evidence_by_ref[ref] = Evidence(
            evidence_ref=ref,
            field="Credential-related language",
            value="Credential-related language and a link were both present.",
            source_type="email_body",
        )
        evidence.append(evidence_by_ref[ref])
        findings.append(_finding(
            "credential_language_with_link", "Credential request language with a link", "The message combines credential-related language with a link. This is an indicator, not proof of phishing.", "medium", [ref, url_indicators[0].evidence_ref],
        ))

    if _URGENCY.search(parsed.body_text) and url_indicators:
        ref = "body:urgent_language"
        evidence.append(Evidence(evidence_ref=ref, field="Urgent wording", value="Urgency wording and a link were both present.", source_type="email_body"))
        findings.append(_finding("urgent_language_with_link", "Urgent wording with a link", "The message pressures the reader to act and includes a link. This is a warning sign, not proof of phishing.", "low", [ref, url_indicators[0].evidence_ref]))

    redirectors = [item for item in url_indicators if item.redirector]
    if redirectors:
        findings.append(_finding("tracking_redirector", "Email tracking redirector", "This link uses a known email click-tracking host; its final destination is unknown because links are not opened.", "low", [item.evidence_ref for item in redirectors]))

    timeline_findings, timeline_signal = _timeline(parsed)
    findings.extend(timeline_findings)

    for indicator in url_indicators:
        try:
            ipaddress.ip_address(indicator.host)
        except ValueError:
            continue
        findings.append(_finding(
            "link_uses_ip_address", "Link uses an IP address", "A link destination uses an IP address instead of a hostname.", "medium", [indicator.evidence_ref],
        ))

    mismatched_links = [item for item in url_indicators if item.visible_text_mismatch]
    if mismatched_links:
        findings.append(_finding(
            "link_visible_text_mismatch", "Visible link text points somewhere else",
            "A link displays a different website address from its actual destination.", "medium",
            [item.evidence_ref for item in mismatched_links],
        ))

    http_urls = [url for url in url_indicators if url.scheme == "http"]
    if http_urls:
        findings.append(_finding(
            "unencrypted_http_link", "Link does not use HTTPS", "At least one extracted link uses HTTP. This does not establish malicious intent.", "low", [url.evidence_ref for url in http_urls],
        ))

    highest = {"high": 3, "medium": 2, "low": 1}
    risk = max((item.severity for item in findings), key=highest.get, default=None)
    if risk in {"high", "medium"}:
        classification = "suspicious"
        risk_level = risk
    elif risk == "low":
        classification = "inconclusive"
        risk_level = "low"
    else:
        classification = "no_known_indicators"
        risk_level = "undetermined"
    benign = []
    if authentication.dmarc == "pass" and (authentication.spf_alignment == "aligned" or authentication.dkim_alignment == "aligned"):
        benign.append("DMARC pass is supported by an aligned DKIM signature." if authentication.dkim_alignment == "aligned" else "DMARC pass is supported by aligned SPF.")
    auth_text = " ".join(value for _, value in headers.get("authentication-results", []))
    if authentication.dmarc == "pass" and re.search(r"\b(?:p|policy)\s*[.=]\s*reject\b", auth_text, re.IGNORECASE):
        benign.append("The message reports DMARC pass under a reject policy. This policy detail comes from the unverified message header.")
    if timeline_signal:
        benign.append("The Date header and earliest Received time are close together. This is a positive signal, not proof of safety.")
    service_host = lambda host: any(host == service or host.endswith("." + service) for service in _KNOWN_MAIL_HOSTS)
    matched_sources = []
    if any(service_host(item.host) for item in url_indicators):
        matched_sources.append("link URLs")
    if any(service_host(domain) for domain in authentication.dkim_domains):
        matched_sources.append("DKIM signing domains")
    if matched_sources:
        benign.append(f"Recognized email-service hosts appear in {' and '.join(matched_sources)}. Legitimate services can also carry malicious mail.")
    return findings, classification, risk_level, benign


_EMAIL_IN_TEXT = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)


def _timeline(parsed: ParsedEmail):
    values = {name.casefold(): value for _, name, value in parsed.headers}
    try:
        sent = parsedate_to_datetime(values["date"])
        if sent.tzinfo is None:
            sent = sent.replace(tzinfo=timezone.utc)
    except (KeyError, TypeError, ValueError, OverflowError):
        sent = None
    findings = []
    received = []
    refs = []
    for ref, name, value in parsed.headers:
        if name.casefold() != "received" or ";" not in value:
            continue
        try:
            moment = parsedate_to_datetime(value.rsplit(";", 1)[1].strip())
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
            received.append(moment)
            refs.append(ref)
        except (TypeError, ValueError, OverflowError):
            continue
    date_ref = next((ref for ref, name, _ in parsed.headers if name.casefold() == "date"), "")
    message_id_ref = next((ref for ref, name, _ in parsed.headers if name.casefold() == "message-id"), "")
    received_earliest = min(received) if received else None
    received_ref = refs[received.index(received_earliest)] if received_earliest else ""
    # Only treat a clearly separated 10-digit Unix timestamp in Message-ID as an epoch.
    msg_id = values.get("message-id", "")
    epoch_match = _EPOCH_TOKEN.search(msg_id)
    if epoch_match:
        try:
            from_epoch = datetime.fromtimestamp(int(epoch_match.group(1)), timezone.utc)
            if any(moment and abs((moment - from_epoch).total_seconds()) > 86400 for moment in (sent, received_earliest)):
                findings.append(_finding("message_id_date_skew", "Message ID timestamp differs from message dates", "A clear 10-digit timestamp in Message-ID differs from the Date or earliest Received time by more than 24 hours. Message-ID formats are not standardized for this purpose.", "low", [message_id_ref, date_ref, received_ref]))
        except (OverflowError, OSError, ValueError):
            pass
    for ref, name, value in parsed.headers:
        if name.casefold() != "dkim-signature":
            continue
        timestamp = _DKIM_TIME.search(value)
        if not timestamp:
            continue
        try:
            signed = datetime.fromtimestamp(int(timestamp.group(1)), timezone.utc)
        except (OverflowError, OSError, ValueError):
            continue
        if any(moment and abs((moment - signed).total_seconds()) > 86400 for moment in (sent, received_earliest)):
            findings.append(_finding("dkim_date_skew", "DKIM timestamp differs from message dates", "The DKIM signature timestamp differs from the Date or earliest Received time by more than 24 hours.", "low", [ref, date_ref, received_ref]))
    if not sent or not received_earliest:
        return findings, False
    delta = (received_earliest - sent).total_seconds()
    if abs(delta) > 86400:
        findings.append(_finding("date_received_skew", "Email dates are more than a day apart", "The Date header and earliest Received timestamp differ by over 24 hours. Check sender clock settings and the message's origin.", "low", [date_ref, received_ref]))
    return findings, abs(delta) <= 600


def _finding(rule_id, title, description, severity, refs):
    return Finding(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        source_type="deterministic_rule",
        evidence_refs=list(dict.fromkeys(refs)),
    )


def _address(headers: list[tuple[str, str]]) -> str:
    return parseaddr(headers[0][1])[1] if headers else ""


def _domain(address: str) -> str:
    try:
        return address.rsplit("@", 1)[1].rstrip(".").encode("idna").decode("ascii").lower()
    except (IndexError, UnicodeError):
        return ""
