import base64
import hashlib
import hmac
import json
import os
import threading
import time
from collections import defaultdict, deque

from shared.config import get_jwt_expiry_minutes, get_jwt_secret
from shared.users import USERS


_lock = threading.Lock()
_request_log: dict[str, deque[float]] = defaultdict(deque)


def get_api_key() -> str:
    return os.getenv("SECURITY_API_KEY", "change-this-api-key")


def get_rate_limit_requests() -> int:
    return int(os.getenv("RATE_LIMIT_REQUESTS", "60"))


def get_rate_limit_window_seconds() -> int:
    return int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))


def require_api_key(api_key: str | None) -> None:
    expected_key = get_api_key()
    if not api_key or api_key != expected_key:
        raise PermissionError("Invalid or missing API key")


def get_user(headers: dict[str, str]) -> dict | None:
    username = headers.get("X-User") or headers.get("x-user")
    if not username:
        return None

    record = USERS.get(username)
    if not record:
        return None

    return {
        "username": username,
        **record,
    }


def require_user(headers: dict[str, str]) -> dict:
    user = get_user(headers)
    if not user:
        raise PermissionError("Unauthorized")
    return user


def require_admin(headers: dict[str, str]) -> dict:
    user = require_user(headers)
    if user.get("role") != "admin":
        raise PermissionError("Forbidden")
    return user


def get_rate_limit_identifier(headers: dict[str, str], remote_addr: str | None) -> str:
    forwarded_for = headers.get("X-Forwarded-For") or headers.get("x-forwarded-for")
    client_host = forwarded_for.split(",")[0].strip() if forwarded_for else None
    return client_host or remote_addr or "unknown"


def enforce_rate_limit(identifier: str) -> None:
    now = time.time()
    window = get_rate_limit_window_seconds()
    limit = get_rate_limit_requests()

    with _lock:
        requests = _request_log[identifier]
        while requests and now - requests[0] >= window:
            requests.popleft()
        if len(requests) >= limit:
            raise RuntimeError("Rate limit exceeded")
        requests.append(now)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def issue_jwt(subject: str, scope: str = "investigation") -> str:
    issued_at = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": subject,
        "scope": scope,
        "iat": issued_at,
        "exp": issued_at + (get_jwt_expiry_minutes() * 60),
    }
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    signature = hmac.new(get_jwt_secret().encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def require_jwt(token: str | None, expected_scope: str = "investigation") -> dict:
    if not token:
        raise PermissionError("Missing bearer token")

    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError as exc:
        raise PermissionError("Invalid bearer token") from exc

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    expected_signature = hmac.new(
        get_jwt_secret().encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).digest()

    if not hmac.compare_digest(_b64url_encode(expected_signature), signature_b64):
        raise PermissionError("Invalid bearer token")

    payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    if payload.get("scope") != expected_scope:
        raise PermissionError("Invalid bearer token scope")
    if int(payload.get("exp", 0)) < int(time.time()):
        raise PermissionError("Invalid bearer token")
    return payload
