"""AlgoVoi webhook signature verifier — v1 (HMAC-SHA256) and v2 (HKDF-SHA256 + HMAC-SHA384)."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import WebhookVerificationError

# Header name used by the AlgoVoi gateway
SIGNATURE_HEADER = "X-AlgoVoi-Signature"

# Default replay-prevention window (seconds)
DEFAULT_TOLERANCE = 300

# Supported event types
KNOWN_EVENT_TYPES = frozenset({"payment.confirmed"})

_SIG_RE = re.compile(
    r"^t=(?P<ts>\d+),v1=(?P<v1>[0-9a-f]{64})(?:,v2=(?P<v2>[0-9a-f]{96}))?$"
)


def _derive_v2_key(secret_bytes: bytes) -> bytes:
    """HKDF-SHA256 key derivation matching the gateway _sign() implementation."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=48,
        salt=b"algovoi-webhook-v2-pqc",
        info=b"hmac-sha384-outbound",
    )
    return hkdf.derive(secret_bytes)


def _compute_sigs(secret: str, ts: int, body: bytes) -> tuple[str, str]:
    """Return (v1_hex, v2_hex) for the given secret, timestamp, and body."""
    secret_bytes = secret.encode()
    signed_payload = f"{ts}.".encode() + body
    v1 = hmac.new(secret_bytes, signed_payload, hashlib.sha256).hexdigest()
    v2_key = _derive_v2_key(secret_bytes)
    v2 = hmac.new(v2_key, signed_payload, hashlib.sha384).hexdigest()
    return v1, v2


def verify_webhook(
    *,
    payload: bytes,
    secret: str,
    signature_header: str,
    tolerance: int = DEFAULT_TOLERANCE,
    require_v2: bool = False,
) -> dict[str, Any]:
    """Verify an AlgoVoi webhook signature and return the parsed event payload.

    Parameters
    ----------
    payload:
        The raw request body bytes exactly as received (do not decode first).
    secret:
        The webhook signing secret for the tenant (``algvw_*`` prefixed string).
    signature_header:
        The value of the ``X-AlgoVoi-Signature`` header.
    tolerance:
        Maximum age (seconds) of a valid signature. Default 300. Pass ``0``
        to disable staleness checking (test environments only).
    require_v2:
        If ``True`` the v2 component *must* be present and valid.  Default
        ``False`` (v2 is validated when present; absent v2 is accepted).

    Returns
    -------
    dict
        The parsed JSON event object.

    Raises
    ------
    WebhookVerificationError
        On any verification failure.  Inspect ``.code`` for the specific
        failure mode.
    """
    # ------------------------------------------------------------------ #
    # 1. Presence check                                                    #
    # ------------------------------------------------------------------ #
    trimmed_header = signature_header.strip() if signature_header else ""
    if not trimmed_header:
        raise WebhookVerificationError(
            "MISSING_SIGNATURE",
            "X-AlgoVoi-Signature header is absent",
        )

    # ------------------------------------------------------------------ #
    # 2. Parse header                                                      #
    # ------------------------------------------------------------------ #
    m = _SIG_RE.match(trimmed_header)
    if not m:
        raise WebhookVerificationError(
            "MALFORMED_SIGNATURE",
            f"Signature header does not match expected format t=<unix>,v1=<sha256hex>[,v2=<sha384hex>]: {signature_header!r}",
        )

    ts = int(m.group("ts"))
    received_v1: str = m.group("v1")
    received_v2: str | None = m.group("v2")

    # ------------------------------------------------------------------ #
    # 3. Staleness check                                                   #
    # ------------------------------------------------------------------ #
    if tolerance > 0:
        age = abs(int(time.time()) - ts)
        if age > tolerance:
            raise WebhookVerificationError(
                "STALE_SIGNATURE",
                f"Signature timestamp {ts} is {age}s old (tolerance {tolerance}s)",
            )

    # ------------------------------------------------------------------ #
    # 4. HMAC computation                                                  #
    # ------------------------------------------------------------------ #
    expected_v1, expected_v2 = _compute_sigs(secret, ts, payload)

    # ------------------------------------------------------------------ #
    # 5. Signature comparison                                              #
    # ------------------------------------------------------------------ #
    v1_ok = hmac.compare_digest(received_v1, expected_v1)

    if received_v2 is not None:
        v2_ok = hmac.compare_digest(received_v2, expected_v2)
    else:
        v2_ok = not require_v2  # absent v2 is fine unless caller requires it

    if not v1_ok or not v2_ok:
        raise WebhookVerificationError(
            "INVALID_SIGNATURE",
            "One or more signature components did not match",
        )

    # ------------------------------------------------------------------ #
    # 6. Payload parse                                                     #
    # ------------------------------------------------------------------ #
    try:
        event: dict[str, Any] = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise WebhookVerificationError(
            "INVALID_PAYLOAD",
            f"Payload is not valid JSON: {exc}",
        ) from exc

    if not isinstance(event, dict):
        raise WebhookVerificationError(
            "INVALID_PAYLOAD",
            "Payload root must be a JSON object",
        )

    # ------------------------------------------------------------------ #
    # 7. Event-type check                                                  #
    # ------------------------------------------------------------------ #
    event_type = event.get("type")
    if event_type not in KNOWN_EVENT_TYPES:
        raise WebhookVerificationError(
            "UNKNOWN_EVENT_TYPE",
            f"Unrecognised event type: {event_type!r}",
        )

    return event
