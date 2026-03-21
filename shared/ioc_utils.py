import ipaddress
import re


IOC_TYPE_TO_BUCKET = {
    "ip": "ips",
    "domain": "domains",
    "email": "emails",
    "username": "usernames",
    "hostname": "hostnames",
    "hash": "hashes",
}

IOC_BUCKET_TO_TYPE = {value: key for key, value in IOC_TYPE_TO_BUCKET.items()}
IOC_SUPPORTED_TYPES = set(IOC_TYPE_TO_BUCKET)

IOC_EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", re.IGNORECASE)
IOC_DOMAIN_PATTERN = re.compile(r"\b(?=.{4,253}\b)(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}\b", re.IGNORECASE)
IOC_MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
IOC_SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
IOC_SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
IOC_MAX_TEXT_VALUES = 200
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{2,128}$")
HOSTNAME_PATTERN = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9._-]+(?<!-)$")


def safe_string(value) -> str:
    return str(value or "").strip()


def flatten_text_values(value, bucket: list[str], limit: int = IOC_MAX_TEXT_VALUES):
    if len(bucket) >= limit or value is None:
        return
    if isinstance(value, dict):
        for item in value.values():
            flatten_text_values(item, bucket, limit)
            if len(bucket) >= limit:
                return
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            flatten_text_values(item, bucket, limit)
            if len(bucket) >= limit:
                return
        return
    text = safe_string(value)
    if text:
        bucket.append(text)


def dedupe_preserve(values, *, transform=None) -> list[str]:
    seen = set()
    deduped = []
    for value in values:
        text = safe_string(value)
        if not text:
            continue
        transformed = transform(text) if callable(transform) else text
        normalized = safe_string(transformed)
        if not normalized:
            continue
        marker = normalized.lower()
        if marker in seen:
            continue
        seen.add(marker)
        deduped.append(normalized)
    return deduped


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(safe_string(value))
        return True
    except ValueError:
        return False


def looks_like_domain(value: str) -> bool:
    text = safe_string(value).lower()
    if not text or "@" in text or is_valid_ip(text):
        return False
    return bool(IOC_DOMAIN_PATTERN.fullmatch(text))


def looks_like_hostname(value: str) -> bool:
    text = safe_string(value)
    if not text or "." not in text or "@" in text or is_valid_ip(text):
        return False
    return bool(HOSTNAME_PATTERN.fullmatch(text))


def looks_like_username(value: str) -> bool:
    text = safe_string(value)
    if not text or "@" in text or "." in text or is_valid_ip(text):
        return False
    return bool(USERNAME_PATTERN.fullmatch(text))


def normalize_ioc_type(ioc_type: str) -> str:
    text = safe_string(ioc_type).lower()
    if text.endswith("es") and text[:-2] in IOC_SUPPORTED_TYPES:
        return text[:-2]
    if text.endswith("s") and text[:-1] in IOC_SUPPORTED_TYPES:
        return text[:-1]
    return text


def normalize_ioc_value(ioc_type: str, value: str) -> str:
    normalized_type = normalize_ioc_type(ioc_type)
    text = safe_string(value)
    if normalized_type in {"domain", "email", "username", "hostname"}:
        return text.lower()
    if normalized_type == "ip":
        return text
    if normalized_type == "hash":
        return text.lower()
    return text


def validate_ioc_value(ioc_type: str, value: str) -> bool:
    normalized_type = normalize_ioc_type(ioc_type)
    text = safe_string(value)
    if not text:
        return False
    if normalized_type == "ip":
        return is_valid_ip(text)
    if normalized_type == "email":
        return bool(IOC_EMAIL_PATTERN.fullmatch(text))
    if normalized_type == "domain":
        return looks_like_domain(text)
    if normalized_type == "hostname":
        return looks_like_hostname(text)
    if normalized_type == "username":
        return looks_like_username(text)
    if normalized_type == "hash":
        return bool(
            IOC_MD5_PATTERN.fullmatch(text)
            or IOC_SHA1_PATTERN.fullmatch(text)
            or IOC_SHA256_PATTERN.fullmatch(text)
        )
    return False


def _collect_provided_iocs(*sources: dict) -> dict[str, list[str]]:
    buckets = {bucket: [] for bucket in IOC_BUCKET_TO_TYPE}
    for source in sources:
        payload = source if isinstance(source, dict) else {}
        iocs = payload.get("iocs") if isinstance(payload.get("iocs"), dict) else payload
        if not isinstance(iocs, dict):
            continue
        for bucket, values in buckets.items():
            provided_values = iocs.get(bucket) or []
            if isinstance(provided_values, (list, tuple, set)):
                values.extend(provided_values)
            elif provided_values:
                values.append(provided_values)
    return buckets


def extract_iocs_from_alert(alert: dict) -> dict[str, list[str]]:
    payload = alert if isinstance(alert, dict) else {}
    details = payload.get("details") if isinstance(payload.get("details"), dict) else {}
    raw = payload.get("raw") if isinstance(payload.get("raw"), dict) else {}
    enrichment = payload.get("enrichment") if isinstance(payload.get("enrichment"), dict) else {}
    provided = _collect_provided_iocs(payload, details, raw, enrichment)

    text_values: list[str] = []
    flatten_text_values(payload, text_values)
    flatten_text_values(details, text_values)
    flatten_text_values(raw, text_values)
    flatten_text_values(enrichment, text_values)
    corpus = "\n".join(text_values)

    source_candidates = [
        payload.get("ip"),
        payload.get("source_ip"),
        payload.get("sourceIp"),
        payload.get("src_ip"),
        payload.get("client_ip"),
        payload.get("destination_ip"),
        payload.get("destinationIp"),
        payload.get("dest_ip"),
        payload.get("dst_ip"),
        details.get("ip"),
        details.get("source_ip"),
        details.get("sourceIp"),
        details.get("destination_ip"),
        details.get("destinationIp"),
        raw.get("ip"),
        raw.get("source_ip"),
        raw.get("sourceIp"),
        raw.get("destination_ip"),
        raw.get("destinationIp"),
        enrichment.get("ip"),
        enrichment.get("destination_ip"),
        enrichment.get("destinationIp"),
    ]

    emails = dedupe_preserve(
        [
            *provided["emails"],
            *(match.group(0) for match in IOC_EMAIL_PATTERN.finditer(corpus)),
            payload.get("email"),
            payload.get("user_email"),
            payload.get("account_email"),
            details.get("email"),
            details.get("user_email"),
            details.get("account_email"),
            raw.get("email"),
            raw.get("user_email"),
            enrichment.get("email"),
        ],
        transform=lambda value: normalize_ioc_value("email", value) if validate_ioc_value("email", value) else "",
    )
    email_domains = [entry.split("@", 1)[1] for entry in emails if "@" in entry]

    ips = dedupe_preserve(
        [
            *provided["ips"],
            *source_candidates,
            *(match.group(0) for match in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", corpus)),
        ],
        transform=lambda value: normalize_ioc_value("ip", value) if validate_ioc_value("ip", value) else "",
    )

    domains = dedupe_preserve(
        [
            *provided["domains"],
            *email_domains,
            *(match.group(0) for match in IOC_DOMAIN_PATTERN.finditer(corpus)),
            payload.get("domain"),
            details.get("domain"),
            raw.get("domain"),
            enrichment.get("domain"),
        ],
        transform=lambda value: normalize_ioc_value("domain", value) if validate_ioc_value("domain", value) else "",
    )

    usernames = dedupe_preserve(
        [
            *provided["usernames"],
            payload.get("user"),
            payload.get("user_id"),
            payload.get("userId"),
            payload.get("username"),
            payload.get("account"),
            payload.get("principal"),
            details.get("user"),
            details.get("user_id"),
            details.get("userId"),
            details.get("username"),
            details.get("account"),
            details.get("principal"),
            raw.get("user"),
            raw.get("user_id"),
            raw.get("userId"),
            raw.get("username"),
            raw.get("account"),
            raw.get("principal"),
            enrichment.get("username"),
            enrichment.get("account"),
        ],
        transform=lambda value: normalize_ioc_value("username", value) if validate_ioc_value("username", value) else "",
    )

    hostnames = dedupe_preserve(
        [
            *provided["hostnames"],
            payload.get("hostname"),
            payload.get("host"),
            payload.get("host_name"),
            payload.get("endpoint"),
            payload.get("device_name"),
            details.get("hostname"),
            details.get("host"),
            details.get("host_name"),
            details.get("endpoint"),
            details.get("device_name"),
            raw.get("hostname"),
            raw.get("host"),
            raw.get("host_name"),
            raw.get("endpoint"),
            enrichment.get("hostname"),
        ],
        transform=lambda value: normalize_ioc_value("hostname", value) if validate_ioc_value("hostname", value) else "",
    )

    hashes = dedupe_preserve(
        [
            *provided["hashes"],
            *(match.group(0) for match in IOC_MD5_PATTERN.finditer(corpus)),
            *(match.group(0) for match in IOC_SHA1_PATTERN.finditer(corpus)),
            *(match.group(0) for match in IOC_SHA256_PATTERN.finditer(corpus)),
            payload.get("hash"),
            payload.get("file_hash"),
            payload.get("sha1"),
            payload.get("sha256"),
            payload.get("md5"),
            details.get("hash"),
            details.get("file_hash"),
            details.get("sha1"),
            details.get("sha256"),
            details.get("md5"),
            raw.get("hash"),
            raw.get("file_hash"),
            raw.get("sha1"),
            raw.get("sha256"),
            raw.get("md5"),
            enrichment.get("hash"),
        ],
        transform=lambda value: safe_string(value) if validate_ioc_value("hash", value) else "",
    )

    return {
        "ips": ips,
        "domains": domains,
        "emails": emails,
        "usernames": usernames,
        "hostnames": hostnames,
        "hashes": hashes,
    }


def iter_ioc_items(iocs: dict) -> list[tuple[str, str, str, str]]:
    items: list[tuple[str, str, str, str]] = []
    payload = iocs if isinstance(iocs, dict) else {}
    for bucket, values in payload.items():
        normalized_bucket = safe_string(bucket).lower()
        ioc_type = IOC_BUCKET_TO_TYPE.get(normalized_bucket)
        if not ioc_type:
            continue
        for value in values or []:
            raw_value = safe_string(value)
            normalized_value = normalize_ioc_value(ioc_type, raw_value)
            if not validate_ioc_value(ioc_type, normalized_value):
                continue
            items.append((ioc_type, normalized_bucket, raw_value, normalized_value))
    return items
