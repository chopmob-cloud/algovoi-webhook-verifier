"""Unit tests for algovoi_webhook_verifier.verify."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from algovoi_webhook_verifier import WebhookVerificationError, verify_webhook

# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

SECRET = "algvw_test_unit_secret"
NOW = 1748650000  # fixed timestamp for all tests


def _derive_v2_key(secret_bytes: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=48,
        salt=b"algovoi-webhook-v2-pqc",
        info=b"hmac-sha384-outbound",
    ).derive(secret_bytes)


def _sign(secret: str, ts: int, body: bytes) -> str:
    sb = secret.encode()
    sp = f"{ts}.".encode() + body
    v1 = hmac.new(sb, sp, hashlib.sha256).hexdigest()
    v2_key = _derive_v2_key(sb)
    v2 = hmac.new(v2_key, sp, hashlib.sha384).hexdigest()
    return f"t={ts},v1={v1},v2={v2}"


def _payment_body(**overrides) -> bytes:
    data = {
        "id": "evt_unit_001",
        "type": "payment.confirmed",
        "created": NOW,
        "api_version": "2024-01-01",
        "data": {},
    }
    data.update(overrides)
    return json.dumps(data, separators=(",", ":")).encode()


def _call(body=None, secret=SECRET, ts=NOW, **kw):
    """Helper: sign body with secret+ts and call verify_webhook with tolerance=0."""
    if body is None:
        body = _payment_body()
    header = _sign(secret, ts, body)
    return verify_webhook(
        payload=body,
        secret=secret,
        signature_header=header,
        tolerance=0,
        **kw,
    )


# --------------------------------------------------------------------------- #
# Happy-path                                                                   #
# --------------------------------------------------------------------------- #

class TestHappyPath:
    def test_returns_parsed_event(self):
        event = _call()
        assert event["type"] == "payment.confirmed"
        assert event["id"] == "evt_unit_001"

    def test_v1_only_accepted_by_default(self):
        body = _payment_body()
        sb = SECRET.encode()
        sp = f"{NOW}.".encode() + body
        v1 = hmac.new(sb, sp, hashlib.sha256).hexdigest()
        header = f"t={NOW},v1={v1}"
        event = verify_webhook(payload=body, secret=SECRET, signature_header=header, tolerance=0)
        assert event["type"] == "payment.confirmed"

    def test_v2_validated_when_present(self):
        # Passing require_v2=True with a full sig should succeed
        event = _call(require_v2=True)
        assert event["type"] == "payment.confirmed"

    def test_whitespace_trimmed_from_header(self):
        body = _payment_body()
        header = "  " + _sign(SECRET, NOW, body) + "  "
        event = verify_webhook(payload=body, secret=SECRET, signature_header=header, tolerance=0)
        assert event["type"] == "payment.confirmed"

    def test_custom_tolerance_accepted(self):
        body = _payment_body()
        # ts = NOW - 100, fake time = NOW → age = 100 < tolerance 200
        old_ts = NOW - 100
        header = _sign(SECRET, old_ts, body)
        with patch("algovoi_webhook_verifier.verify.time") as mock_time:
            mock_time.time.return_value = NOW
            event = verify_webhook(payload=body, secret=SECRET, signature_header=header, tolerance=200)
        assert event["type"] == "payment.confirmed"

    def test_unicode_body(self):
        body = json.dumps({
            "id": "evt_u_001",
            "type": "payment.confirmed",
            "created": NOW,
            "api_version": "2024-01-01",
            "data": {"label": "café"},
        }, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        header = _sign(SECRET, NOW, body)
        event = verify_webhook(payload=body, secret=SECRET, signature_header=header, tolerance=0)
        assert event["data"]["label"] == "café"


# --------------------------------------------------------------------------- #
# MISSING_SIGNATURE                                                            #
# --------------------------------------------------------------------------- #

class TestMissingSignature:
    @pytest.mark.parametrize("header", ["", None])
    def test_empty_or_none_header(self, header):
        body = _payment_body()
        with pytest.raises(WebhookVerificationError) as exc_info:
            verify_webhook(payload=body, secret=SECRET, signature_header=header or "", tolerance=0)
        assert exc_info.value.code == "MISSING_SIGNATURE"

    def test_error_message_contains_header_name(self):
        with pytest.raises(WebhookVerificationError) as exc_info:
            verify_webhook(payload=_payment_body(), secret=SECRET, signature_header="", tolerance=0)
        assert "X-AlgoVoi-Signature" in exc_info.value.message


# --------------------------------------------------------------------------- #
# MALFORMED_SIGNATURE                                                          #
# --------------------------------------------------------------------------- #

class TestMalformedSignature:
    @pytest.mark.parametrize("bad_header", [
        "v1=abc123",
        "t=abc,v1=abc",                         # non-numeric ts
        "t=123,v2=abc",                          # missing v1
        "t=123,v1=" + "a" * 63,                  # v1 too short
        "t=123,v1=" + "a" * 65,                  # v1 too long
        "t=123,v1=" + "g" * 64,                  # non-hex v1
        "randomgarbage",
    ])
    def test_rejects_bad_format(self, bad_header):
        with pytest.raises(WebhookVerificationError) as exc_info:
            verify_webhook(payload=_payment_body(), secret=SECRET, signature_header=bad_header, tolerance=0)
        assert exc_info.value.code == "MALFORMED_SIGNATURE"


# --------------------------------------------------------------------------- #
# STALE_SIGNATURE                                                              #
# --------------------------------------------------------------------------- #

class TestStaleSignature:
    def test_expired_timestamp(self):
        body = _payment_body()
        old_ts = NOW - 600
        header = _sign(SECRET, old_ts, body)
        with patch("algovoi_webhook_verifier.verify.time") as mock_time:
            mock_time.time.return_value = NOW
            with pytest.raises(WebhookVerificationError) as exc_info:
                verify_webhook(payload=body, secret=SECRET, signature_header=header, tolerance=300)
        assert exc_info.value.code == "STALE_SIGNATURE"

    def test_future_timestamp_beyond_tolerance(self):
        body = _payment_body()
        future_ts = NOW + 600
        header = _sign(SECRET, future_ts, body)
        with patch("algovoi_webhook_verifier.verify.time") as mock_time:
            mock_time.time.return_value = NOW
            with pytest.raises(WebhookVerificationError) as exc_info:
                verify_webhook(payload=body, secret=SECRET, signature_header=header, tolerance=300)
        assert exc_info.value.code == "STALE_SIGNATURE"

    def test_tolerance_zero_bypasses_check(self):
        body = _payment_body()
        old_ts = NOW - 99999
        header = _sign(SECRET, old_ts, body)
        # Should NOT raise even though ts is ancient
        event = verify_webhook(payload=body, secret=SECRET, signature_header=header, tolerance=0)
        assert event["type"] == "payment.confirmed"


# --------------------------------------------------------------------------- #
# INVALID_SIGNATURE                                                            #
# --------------------------------------------------------------------------- #

class TestInvalidSignature:
    def test_wrong_secret(self):
        body = _payment_body()
        header = _sign("algvw_wrong_secret", NOW, body)
        with pytest.raises(WebhookVerificationError) as exc_info:
            verify_webhook(payload=body, secret=SECRET, signature_header=header, tolerance=0)
        assert exc_info.value.code == "INVALID_SIGNATURE"

    def test_tampered_body(self):
        body = _payment_body()
        header = _sign(SECRET, NOW, body)
        tampered = body.replace(b"evt_unit_001", b"evt_tampered")
        with pytest.raises(WebhookVerificationError) as exc_info:
            verify_webhook(payload=tampered, secret=SECRET, signature_header=header, tolerance=0)
        assert exc_info.value.code == "INVALID_SIGNATURE"

    def test_corrupted_v1_hex(self):
        body = _payment_body()
        header = _sign(SECRET, NOW, body)
        # Flip last character of v1
        corrupted = header[:-1] + ("0" if header[-1] != "0" else "1")
        with pytest.raises(WebhookVerificationError) as exc_info:
            verify_webhook(payload=body, secret=SECRET, signature_header=corrupted, tolerance=0)
        assert exc_info.value.code == "INVALID_SIGNATURE"

    def test_require_v2_fails_when_v2_absent(self):
        body = _payment_body()
        sb = SECRET.encode()
        sp = f"{NOW}.".encode() + body
        v1 = hmac.new(sb, sp, hashlib.sha256).hexdigest()
        header = f"t={NOW},v1={v1}"  # no v2
        with pytest.raises(WebhookVerificationError) as exc_info:
            verify_webhook(payload=body, secret=SECRET, signature_header=header, tolerance=0, require_v2=True)
        assert exc_info.value.code == "INVALID_SIGNATURE"

    def test_corrupted_v2_hex(self):
        body = _payment_body()
        header = _sign(SECRET, NOW, body)
        # Corrupt the v2 component
        parts = header.split(",v2=")
        bad_v2 = parts[1][:-1] + ("0" if parts[1][-1] != "0" else "1")
        corrupted = parts[0] + ",v2=" + bad_v2
        with pytest.raises(WebhookVerificationError) as exc_info:
            verify_webhook(payload=body, secret=SECRET, signature_header=corrupted, tolerance=0)
        assert exc_info.value.code == "INVALID_SIGNATURE"


# --------------------------------------------------------------------------- #
# INVALID_PAYLOAD                                                              #
# --------------------------------------------------------------------------- #

class TestInvalidPayload:
    def test_not_json(self):
        body = b"not-json"
        header = _sign(SECRET, NOW, body)
        with pytest.raises(WebhookVerificationError) as exc_info:
            verify_webhook(payload=body, secret=SECRET, signature_header=header, tolerance=0)
        assert exc_info.value.code == "INVALID_PAYLOAD"

    def test_json_array_root(self):
        body = b'["a","b"]'
        header = _sign(SECRET, NOW, body)
        with pytest.raises(WebhookVerificationError) as exc_info:
            verify_webhook(payload=body, secret=SECRET, signature_header=header, tolerance=0)
        assert exc_info.value.code == "INVALID_PAYLOAD"

    def test_truncated_json(self):
        body = b'{"type": "payment.confirmed"'  # missing closing brace
        header = _sign(SECRET, NOW, body)
        with pytest.raises(WebhookVerificationError) as exc_info:
            verify_webhook(payload=body, secret=SECRET, signature_header=header, tolerance=0)
        assert exc_info.value.code == "INVALID_PAYLOAD"


# --------------------------------------------------------------------------- #
# UNKNOWN_EVENT_TYPE                                                           #
# --------------------------------------------------------------------------- #

class TestUnknownEventType:
    @pytest.mark.parametrize("event_type", [
        "refund.issued",
        "payment.failed",
        "mandate.cancelled",
        None,
        "",
    ])
    def test_unknown_types(self, event_type):
        data = {
            "id": "evt_unk",
            "type": event_type,
            "created": NOW,
            "api_version": "2024-01-01",
            "data": {},
        }
        body = json.dumps(data, separators=(",", ":")).encode()
        header = _sign(SECRET, NOW, body)
        with pytest.raises(WebhookVerificationError) as exc_info:
            verify_webhook(payload=body, secret=SECRET, signature_header=header, tolerance=0)
        assert exc_info.value.code == "UNKNOWN_EVENT_TYPE"


# --------------------------------------------------------------------------- #
# Error object shape                                                           #
# --------------------------------------------------------------------------- #

class TestErrorObject:
    def test_error_has_code_and_message(self):
        with pytest.raises(WebhookVerificationError) as exc_info:
            verify_webhook(payload=_payment_body(), secret=SECRET, signature_header="", tolerance=0)
        err = exc_info.value
        assert isinstance(err.code, str)
        assert isinstance(err.message, str)
        assert str(err) == err.message

    def test_repr_contains_code_and_message(self):
        err = WebhookVerificationError("INVALID_SIGNATURE", "test msg")
        r = repr(err)
        assert "INVALID_SIGNATURE" in r
        assert "test msg" in r
