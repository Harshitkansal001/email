from pathlib import Path

import pytest

from app.security.validation import MAX_EML_BYTES
from app.services import email_parser
from app.services.email_parser import MessageInputError, parse_email


SAMPLES = Path(__file__).parents[2] / "samples"
SUSPICIOUS_EML = (SAMPLES / "suspicious-example.eml").read_bytes()


def test_analyze_eml_returns_explainable_findings_without_attachment_bytes(client):
    response = client.post(
        "/api/v1/analyze/file",
        content=SUSPICIOUS_EML,
        headers={"Content-Type": "application/octet-stream"},
    )

    assert response.status_code == 200
    report = response.json()
    assert report["schema_version"] == "1.0"
    assert report["classification"] == "suspicious"
    assert {finding["rule_id"] for finding in report["findings"]} >= {
        "reply_to_domain_mismatch",
        "reported_authentication_failure",
        "credential_language_with_link",
        "risky_attachment_extension",
    }
    assert report["authentication"]["spf"] == "fail"
    assert report["routing"]["hops"][0]["candidate_ips"] == ["203.0.113.7"]
    assert {item["address"]: item["category"] for item in report["ip_indicators"]} == {
        "203.0.113.7": "reserved",
        "192.0.2.9": "reserved",
    }
    assert report["attachments"][0]["filename"] == "statement.xlsm"
    assert "U0FNUExF" not in response.text
    assert report["classifier"]["status"] == "not_configured"
    assert report["enrichment"]["status"] == "not_requested"


def test_header_only_analysis_keeps_missing_evidence_unknown_and_ignores_body(client):
    response = client.post("/api/v1/analyze/headers", json={
        "raw_headers": "From: analyst@example.org\r\nSubject: Test\r\n\r\npassword https://example.net/",
    })

    assert response.status_code == 200
    report = response.json()
    assert report["input_type"] == "headers"
    assert report["authentication"]["spf"] == "unknown"
    assert report["routing"]["status"] == "insufficient_evidence"
    assert report["url_indicators"] == []
    assert report["classification"] == "no_known_indicators"
    assert any("Header-only input" in item for item in report["limitations"])
    assert all("password" not in item["value"] for item in report["evidence"])


def test_benign_sample_does_not_claim_message_is_safe(client):
    response = client.post(
        "/api/v1/analyze/file",
        content=(SAMPLES / "benign-example.eml").read_bytes(),
        headers={"Content-Type": "application/octet-stream"},
    )

    assert response.status_code == 200
    report = response.json()
    assert report["classification"] == "no_known_indicators"
    assert any("does not establish" in item for item in report["limitations"])


def test_repeated_links_share_one_indicator(client):
    response = client.post("/api/v1/analyze/file", content=(
        b"From: analyst@example.org\r\nContent-Type: text/plain\r\n\r\n"
        b"https://example.org/a https://example.org/b"
    ), headers={"Content-Type": "application/octet-stream"})

    assert response.status_code == 200
    assert len(response.json()["url_indicators"]) == 2


def test_routing_ignores_dotted_server_id_timestamp(client):
    response = client.post("/api/v1/analyze/headers", json={"raw_headers": (
        "From: sender@example.org\r\n"
        "Received: from sender.example.net by mx.google.com with ESMTPS id abc2026.10.11.11.22.31; Tue, 12 Oct 2026 10:00:00 +0000\r\n"
    )})
    assert response.status_code == 200
    report = response.json()
    assert report["routing"]["hops"][0]["candidate_ips"] == []
    assert all(item["address"] != "10.11.11.22" for item in report["ip_indicators"])


def test_dates_and_message_id_epoch_are_compared(client):
    response = client.post("/api/v1/analyze/headers", json={"raw_headers": (
        "From: sender@example.org\r\n"
        "Date: Mon, 12 Oct 2026 10:00:00 +0000\r\n"
        "Message-ID: <id-1790000000@example.org>\r\n"
        "Received: from relay.example.org by mx.example.org; Mon, 12 Oct 2026 10:05:00 +0000\r\n"
    )})
    assert response.status_code == 200
    report = response.json()
    assert "message_id_date_skew" in {item["rule_id"] for item in report["findings"]}
    assert any("Date header and earliest Received" in item for item in report["benign_indicators"])


def test_authentication_alignment_and_url_privacy(client):
    response = client.post("/api/v1/analyze/file", content=(
        b"From: Example Team <person@example.com>\r\n"
        b"Return-Path: <bounce@example.com>\r\n"
        b"Authentication-Results: mx; spf=pass smtp.mailfrom=bounce@example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"https://hubspotlinks.com/redirect/abcdefghijklmnopqrstuvwx?email=person@example.com&token=secret&campaign=spring\n"
    ), headers={"Content-Type": "application/octet-stream"})
    assert response.status_code == 200
    report = response.json()
    assert report["authentication"]["spf_alignment"] == "aligned"
    assert report["authentication"]["dkim_alignment"] == "aligned"
    link = report["url_indicators"][0]
    assert link["redirector"] is True
    assert "secret" not in str(link)
    assert "person%40example.com" not in str(link)
    assert "spring" in (link["query"] or "")


def test_enrichment_is_opt_in_and_uses_public_registry_data(monkeypatch):
    from ipaddress import ip_network
    from app.services import ip_enrichment
    from app.schemas.analysis import IpIndicator

    assert ip_enrichment._safe_registry_url("https://rdap.apnic.net/rdap/")
    assert not ip_enrichment._safe_registry_url("http://127.0.0.1/")
    with pytest.raises(ValueError, match="Untrusted registry"):
        ip_enrichment._get_json("https://127.0.0.1/latest/meta-data/")
    monkeypatch.setattr(ip_enrichment, "_bootstrap", lambda version: [(ip_network("139.0.0.0/8"), "https://rdap.apnic.net/rdap")])
    monkeypatch.setattr(ip_enrichment, "_get_json", lambda url: {"name": "Example Network", "country": "IN", "entities": []})
    item = IpIndicator(address="139.180.17.170", category="public", evidence_refs=["header:Received:1"])
    assert ip_enrichment.enrich_public_ips([item], False).status == "not_requested"
    result = ip_enrichment.enrich_public_ips([item], True)
    assert result.status == "complete"
    assert result.ip_results[0]["network"] == "Example Network"


def test_received_headers_are_shown_oldest_first_and_ip_scope_is_labeled(client):
    response = client.post("/api/v1/analyze/headers", json={
        "raw_headers": (
            "From: sender@example.org\r\n"
            "Received: from newest [10.0.0.4] by mx.example.org; Tue, 12 Oct 2026 10:00:00 +0000\r\n"
            "Received: from oldest [203.0.113.5] by newest; Tue, 12 Oct 2026 09:00:00 +0000\r\n"
        ),
    })

    report = response.json()
    assert response.status_code == 200
    assert [hop["candidate_ips"] for hop in report["routing"]["hops"]] == [["203.0.113.5"], ["10.0.0.4"]]
    assert {item["address"]: item["category"] for item in report["ip_indicators"]} == {
        "203.0.113.5": "reserved",
        "10.0.0.4": "private",
    }
    assert "not independently verified" in report["routing"]["note"]


def test_empty_and_malformed_inputs_return_structured_errors(client):
    empty = client.post("/api/v1/analyze/file", content=b"", headers={"Content-Type": "application/octet-stream"})
    malformed_headers = client.post("/api/v1/analyze/headers", json={"raw_headers": "not a header"})

    assert empty.status_code == 422
    assert empty.json()["error"]["code"] == "empty_input"
    assert malformed_headers.status_code == 422
    assert malformed_headers.json()["error"]["code"] == "missing_headers"


def test_file_body_limit_is_enforced_before_parsing(client):
    response = client.post(
        "/api/v1/analyze/file",
        content=b"x" * (MAX_EML_BYTES + 1),
        headers={"Content-Type": "application/octet-stream"},
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"


def test_header_byte_limit_cannot_be_bypassed_with_multibyte_text(client):
    response = client.post("/api/v1/analyze/headers", json={"raw_headers": "é" * 32_769})

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "headers_too_large"


def test_invalid_file_media_type_is_rejected(client):
    response = client.post("/api/v1/analyze/file", content=SUSPICIOUS_EML, headers={"Content-Type": "text/plain"})

    assert response.status_code == 415
    assert response.json()["error"]["code"] == "unsupported_media_type"


def test_built_frontend_and_health_are_served(client):
    assert client.get("/api/health").json() == {"status": "ok"}
    page = client.get("/")
    if (SAMPLES.parents[0] / "frontend" / "dist").is_dir():
        assert page.status_code == 200
        assert "Email Threat Forensics" in page.text


def test_excessive_headers_and_mime_depth_are_rejected():
    many_headers = b"".join(b"X-Test: value\r\n" for _ in range(201)) + b"\r\n"
    with pytest.raises(MessageInputError, match="header count"):
        parse_email(many_headers, "eml")

    nested = b"From: test@example.org\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b0\r\n\r\n"
    for index in range(14):
        nested += f"--b{index}\r\nContent-Type: multipart/mixed; boundary=b{index + 1}\r\n\r\n".encode()
    nested += b"--b14\r\nContent-Type: text/plain\r\n\r\nend\r\n"
    for index in reversed(range(15)):
        nested += f"\r\n--b{index}--\r\n".encode()

    with pytest.raises(MessageInputError, match="MIME structure"):
        parse_email(nested, "eml")


def test_message_line_flood_is_rejected_before_stdlib_parser(monkeypatch):
    floods = [
        b"From: analyst@example.org\r\n\r\n" + b"x\r\n" * 100_001,
        (
            b"From: analyst@example.org\r\nMIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\n"
            + b"X-Part: value\r\n" * 5_001
            + b"\r\nbody\r\n--x--\r\n"
        ),
    ]
    monkeypatch.setattr(email_parser.BytesParser, "parsebytes", lambda *_: pytest.fail("parser should not run"))

    for raw in floods:
        with pytest.raises(MessageInputError) as error:
            parse_email(raw, "eml")
        assert error.value.code in {"message_too_many_lines", "message_too_many_headers"}


def test_header_like_line_limit_returns_structured_api_error(client):
    raw = b"From: analyst@example.org\r\n\r\n" + b"X-Part: value\r\n" * 5_001
    response = client.post(
        "/api/v1/analyze/file",
        content=raw,
        headers={"Content-Type": "application/octet-stream"},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "message_too_many_headers"
