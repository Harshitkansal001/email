import ipaddress
import json
import os
import socket
from http.client import HTTPException
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import maxminddb

from app.schemas.analysis import EnrichmentOutput, IpIndicator

_BOOTSTRAP = {
    4: "https://data.iana.org/rdap/ipv4.json",
    6: "https://data.iana.org/rdap/ipv6.json",
}
_REGISTRIES = {"rdap.arin.net", "rdap.apnic.net", "rdap.db.ripe.net", "rdap.lacnic.net", "rdap.afrinic.net"}
_MAX_RESULTS = 5
_MAX_RESPONSE_BYTES = 128_000
_DEFAULT_CITY_DB = Path(__file__).resolve().parents[2] / "data" / "GeoLite2-City.mmdb"
_DEFAULT_ASN_DB = Path(__file__).resolve().parents[2] / "data" / "GeoLite2-ASN.mmdb"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, new_url):
        return None


def enrich_public_ips(indicators: list[IpIndicator], requested: bool, verify_rdns: bool = False) -> EnrichmentOutput:
    public = list(dict.fromkeys(item.address for item in indicators if item.category == "public"))[:_MAX_RESULTS]
    if not public:
        return EnrichmentOutput(status="not_requested", note="No public IP addresses were available to look up.")

    database = _city_database_path()
    asn_database = _asn_database_path()
    results: dict[str, dict[str, str | None]] = {
        address: {"address": address, "country": None} for address in public
    }
    local_available = False
    local_error = False
    if database.is_file():
        try:
            reader = _city_reader(str(database))
            for address in public:
                record = reader.get(address)
                if record:
                    results[address].update(_city_fields(record))
            local_available = True
        except (OSError, maxminddb.InvalidDatabaseError):
            local_error = True
    if asn_database.is_file():
        try:
            reader = _asn_reader(str(asn_database))
            for address in public:
                record = reader.get(address)
                if record:
                    results[address].update(_asn_fields(record))
            local_available = True
        except (OSError, maxminddb.InvalidDatabaseError):
            local_error = True

    if verify_rdns:
        for address in public:
            results[address].update(_forward_confirmed_reverse_dns(address))

    if not requested:
        if not local_available:
            status = "unavailable" if local_error else "not_configured"
            note = "A local MaxMind database could not be read." if local_error else "Install GeoLite2 City and ASN databases for local enrichment; no registry lookup was made."
            return EnrichmentOutput(status="complete" if verify_rdns and not local_error else status,
                                    ip_results=list(results.values()) if verify_rdns else [], note=note)
        return EnrichmentOutput(status="complete", ip_results=list(results.values()),
                                note="Location and network owner use local MaxMind data; reverse DNS, if requested, was queried externally and may be inaccurate.")

    try:
        services = {version: _bootstrap(version) for version in {ipaddress.ip_address(item).version for item in public}}
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        status = "partial" if local_available or verify_rdns else "unavailable"
        note = "Local MaxMind data is available; the public IP registry could not be reached." if local_available else "The public IP registry could not be reached. No registry attribution was added."
        return EnrichmentOutput(status=status, ip_results=list(results.values()) if local_available or verify_rdns else [], note=note)

    for value in public:
        address = ipaddress.ip_address(value)
        try:
            base = next((url for network, url in services[address.version] if address in network), None)
            if not base:
                raise ValueError("No registry service")
            result = _get_json(base.rstrip("/") + "/ip/" + value)
            if not isinstance(result, dict):
                raise ValueError("Invalid registry response")
            country = result.get("country")
            results[value].update({
                "network": str(result.get("name", ""))[:200],
                "organization": _organization(result)[:200],
                "country": country[:2] if isinstance(country, str) and country else None,
            })
        except (OSError, HTTPException, ValueError, KeyError, TypeError, AttributeError, json.JSONDecodeError):
            results[value]["registry_error"] = "Registry lookup unavailable"
    failures = sum("registry_error" in item for item in results.values())
    status = "partial" if failures or local_error else "complete"
    note = "Local MaxMind location is approximate. Registry records identify the registered network, not necessarily the sender or attacker."
    if not local_available and not local_error:
        note = "Registry records identify the registered network, not necessarily the sender or attacker. Install GeoLite2 City for local location estimates."
    elif local_error:
        note = "The MaxMind database could not be read. Registry data may identify the registered network, not the sender or attacker."
    return EnrichmentOutput(status=status, ip_results=list(results.values()), note=note)


def _city_database_path() -> Path:
    return Path(os.environ.get("MAXMIND_CITY_DB_PATH", str(_DEFAULT_CITY_DB))).expanduser()


def _asn_database_path() -> Path:
    return Path(os.environ.get("MAXMIND_ASN_DB_PATH", str(_DEFAULT_ASN_DB))).expanduser()


@lru_cache(maxsize=1)
def _city_reader(path: str):
    return maxminddb.open_database(path)


@lru_cache(maxsize=1)
def _asn_reader(path: str):
    return maxminddb.open_database(path)


def _asn_fields(record: dict) -> dict[str, str]:
    return {key: str(value) for key, value in {
        "asn": record.get("autonomous_system_number"),
        "asn_owner": record.get("autonomous_system_organization"),
    }.items() if value is not None and value != ""}


def _forward_confirmed_reverse_dns(address: str) -> dict[str, str]:
    try:
        hostname = socket.gethostbyaddr(address)[0].rstrip(".").lower()
        resolved = {str(ipaddress.ip_address(item[4][0])) for item in socket.getaddrinfo(hostname, None)}
        confirmed = str(ipaddress.ip_address(address)) in resolved
        return {"ptr_hostname": hostname, "fcrdns": "confirmed" if confirmed else "not_confirmed"}
    except (OSError, socket.gaierror, IndexError):
        return {"fcrdns": "unavailable"}


def _city_fields(record: dict) -> dict[str, str | None]:
    country = record.get("country", {}).get("iso_code") or record.get("registered_country", {}).get("iso_code")
    region = next((item.get("names", {}).get("en") for item in record.get("subdivisions", []) if item.get("names", {}).get("en")), "")
    city = record.get("city", {}).get("names", {}).get("en", "")
    location = record.get("location", {})
    accuracy = location.get("accuracy_radius")
    if accuracy is not None and accuracy >= 500:
        return {"country": str(country) if country else None}
    result: dict[str, str | None] = {
        "country": str(country) if country else None,
        **{key: str(value) for key, value in {
            "region": region,
            "city": city,
            "latitude": location.get("latitude"),
            "longitude": location.get("longitude"),
            "accuracy_radius_km": location.get("accuracy_radius"),
        }.items() if value is not None and value != ""},
    }
    return result


@lru_cache(maxsize=2)
def _bootstrap(version: int):
    doc = _get_json(_BOOTSTRAP[version])
    services = []
    for prefixes, urls in doc["services"]:
        url = next((candidate for candidate in urls if _safe_registry_url(candidate)), None)
        if not url:
            continue
        for prefix in prefixes:
            try:
                services.append((ipaddress.ip_network(prefix), url))
            except ValueError:
                continue
    return services


def _safe_registry_url(url: str) -> bool:
    parsed = urlsplit(url)
    return parsed.scheme == "https" and parsed.hostname in _REGISTRIES and parsed.port in {None, 443} and not parsed.username


def _get_json(url: str):
    if not url.startswith("https://data.iana.org/") and not _safe_registry_url(url.rsplit("/ip/", 1)[0] + "/"):
        raise ValueError("Untrusted registry")
    opener = build_opener(_NoRedirect)
    with opener.open(Request(url, headers={"Accept": "application/rdap+json, application/json", "User-Agent": "EmailThreatForensics/1.0"}), timeout=3) as response:
        if response.status != 200:
            raise ValueError("Registry status")
        body = response.read(_MAX_RESPONSE_BYTES + 1)
    if len(body) > _MAX_RESPONSE_BYTES:
        raise ValueError("Registry response too large")
    return json.loads(body)


def _organization(record: dict) -> str:
    entities = record.get("entities", [])
    if not isinstance(entities, list):
        return ""
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        vcard = entity.get("vcardArray")
        if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
            continue
        for item in vcard[1]:
            if not isinstance(item, list) or len(item) < 4 or item[0] not in {"fn", "org"}:
                continue
            if len(item) > 3:
                value = item[3]
                if isinstance(value, list):
                    value = " ".join(map(str, value))
                if value:
                    return str(value)
    return ""
