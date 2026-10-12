import re
from email.utils import getaddresses, parseaddr

from app.schemas.analysis import AnalysisResponse

_RECEIVED_FOR = re.compile(r"\bfor\s+<([^<>]+)>", re.IGNORECASE)


def recipient_local_parts(headers: list[tuple[str, str, str]]) -> list[str]:
    addresses: list[str] = []
    for _, name, value in headers:
        if name.casefold() in {"to", "delivered-to"}:
            addresses.extend(address for _, address in getaddresses([value]) if address)
        elif name.casefold() == "received":
            addresses.extend(parseaddr(match)[1] for match in _RECEIVED_FOR.findall(value))

    locals_by_casefold: dict[str, str] = {}
    for address in addresses:
        if "@" not in address:
            continue
        local = address.rsplit("@", 1)[0].strip()
        if local:
            locals_by_casefold.setdefault(local.casefold(), local)
    return sorted(locals_by_casefold.values(), key=lambda local: (-len(local), local.casefold()))


def redact_recipient_identifiers(report: AnalysisResponse, local_parts: list[str]) -> AnalysisResponse:
    if not local_parts:
        return report

    def redact(value):
        if isinstance(value, str):
            for local in local_parts:
                verp = re.compile(
                    rf"(?P<token>[^@\s<>;,=]+)-{re.escape(local)}=(?=[^@\s<>;,]*@)",
                    re.IGNORECASE,
                )
                value = verp.sub("[redacted]-[redacted]=", value)
                value = re.sub(re.escape(local), "[redacted]", value, flags=re.IGNORECASE)
            return value
        if isinstance(value, list):
            return [redact(item) for item in value]
        if isinstance(value, dict):
            return {key: redact(item) for key, item in value.items()}
        return value

    return AnalysisResponse.model_validate(redact(report.model_dump()))
