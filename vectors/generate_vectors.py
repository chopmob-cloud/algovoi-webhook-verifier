"""Generate cross-validation vectors for algovoi-webhook-verifier.

Writes JSON fixture files to vectors/valid/ and vectors/invalid/.
Each file is self-contained: it includes the secret, raw body, header,
expected outcome, and (for invalid cases) the expected error code.

Run:
    python vectors/generate_vectors.py
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = Path(__file__).parent


def _derive_v2_key(secret_bytes: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=48,
        salt=b"algovoi-webhook-v2-pqc",
        info=b"hmac-sha384-outbound",
    )
    return hkdf.derive(secret_bytes)


def _sign(secret: str, ts: int, body: bytes) -> str:
    secret_bytes = secret.encode()
    signed_payload = f"{ts}.".encode() + body
    v1 = hmac.new(secret_bytes, signed_payload, hashlib.sha256).hexdigest()
    v2_key = _derive_v2_key(secret_bytes)
    v2 = hmac.new(v2_key, signed_payload, hashlib.sha384).hexdigest()
    return f"t={ts},v1={v1},v2={v2}"


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"  wrote {path.relative_to(ROOT.parent)}")


# --------------------------------------------------------------------------- #
# Shared fixtures                                                              #
# --------------------------------------------------------------------------- #
SECRET = "algvw_test_secret_for_vectors_only"
TS_RECENT = 1748650000  # fixed past timestamp — always valid in tests (tolerance=0)

PAYMENT_CONFIRMED_BODY = json.dumps({
    "id": "evt_test_001",
    "type": "payment.confirmed",
    "created": TS_RECENT,
    "api_version": "2024-01-01",
    "data": {
        "tenant_label": "test-tenant",
        "resource_id": "pay_abc123",
        "chain": "base",
        "asset": {
            "id": "usdc",
            "label": "USDC",
            "decimals": 6,
        },
        "amount_microunits": 1000000,
        "amount_pretty": "1.00 USDC",
        "tx_id": "0xdeadbeef",
        "payer_address": "0xabc",
        "payment_link_token": "tok_test",
        "payment_link_label": "Test Payment",
    },
}, separators=(",", ":")).encode()


def generate() -> None:
    print("Generating vectors…")

    valid_dir = ROOT / "valid"
    invalid_dir = ROOT / "invalid"

    # ----------------------------------------------------------------------- #
    # VALID vectors                                                            #
    # ----------------------------------------------------------------------- #

    # v01 — v1+v2 present, payment.confirmed
    sig = _sign(SECRET, TS_RECENT, PAYMENT_CONFIRMED_BODY)
    _write(valid_dir / "v01_payment_confirmed_v1v2.json", {
        "description": "Valid payment.confirmed with v1+v2 signature",
        "secret": SECRET,
        "timestamp": TS_RECENT,
        "body": PAYMENT_CONFIRMED_BODY.decode(),
        "signature_header": sig,
        "expected": "ok",
    })

    # v02 — v1 only (no v2 component)
    secret_bytes = SECRET.encode()
    sp = f"{TS_RECENT}.".encode() + PAYMENT_CONFIRMED_BODY
    v1_only = hmac.new(secret_bytes, sp, hashlib.sha256).hexdigest()
    _write(valid_dir / "v02_payment_confirmed_v1_only.json", {
        "description": "Valid payment.confirmed with v1-only signature (v2 absent)",
        "secret": SECRET,
        "timestamp": TS_RECENT,
        "body": PAYMENT_CONFIRMED_BODY.decode(),
        "signature_header": f"t={TS_RECENT},v1={v1_only}",
        "expected": "ok",
    })

    # v03 — different secret produces correct sigs for that secret
    SECRET2 = "algvw_second_test_secret_xyz"
    sig2 = _sign(SECRET2, TS_RECENT, PAYMENT_CONFIRMED_BODY)
    _write(valid_dir / "v03_different_secret.json", {
        "description": "Valid with a different secret",
        "secret": SECRET2,
        "timestamp": TS_RECENT,
        "body": PAYMENT_CONFIRMED_BODY.decode(),
        "signature_header": sig2,
        "expected": "ok",
    })

    # v04 — minimal body (only required fields)
    minimal_body = json.dumps({
        "id": "evt_min_001",
        "type": "payment.confirmed",
        "created": TS_RECENT,
        "api_version": "2024-01-01",
        "data": {},
    }, separators=(",", ":")).encode()
    sig4 = _sign(SECRET, TS_RECENT, minimal_body)
    _write(valid_dir / "v04_minimal_payload.json", {
        "description": "Valid payment.confirmed with minimal data object",
        "secret": SECRET,
        "timestamp": TS_RECENT,
        "body": minimal_body.decode(),
        "signature_header": sig4,
        "expected": "ok",
    })

    # v05 — body with unicode / non-ASCII characters
    unicode_body = json.dumps({
        "id": "evt_unicode_001",
        "type": "payment.confirmed",
        "created": TS_RECENT,
        "api_version": "2024-01-01",
        "data": {"label": "Ünïcödé pàyment — café"},
    }, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig5 = _sign(SECRET, TS_RECENT, unicode_body)
    _write(valid_dir / "v05_unicode_payload.json", {
        "description": "Valid payload containing non-ASCII characters",
        "secret": SECRET,
        "timestamp": TS_RECENT,
        "body": unicode_body.decode("utf-8"),
        "signature_header": sig5,
        "expected": "ok",
    })

    # ----------------------------------------------------------------------- #
    # INVALID vectors                                                          #
    # ----------------------------------------------------------------------- #

    # i01 — MISSING_SIGNATURE: empty header
    _write(invalid_dir / "i01_missing_signature.json", {
        "description": "Empty signature header → MISSING_SIGNATURE",
        "secret": SECRET,
        "timestamp": TS_RECENT,
        "body": PAYMENT_CONFIRMED_BODY.decode(),
        "signature_header": "",
        "expected": "error",
        "error_code": "MISSING_SIGNATURE",
    })

    # i02 — MALFORMED_SIGNATURE: header has wrong format
    _write(invalid_dir / "i02_malformed_signature.json", {
        "description": "Header does not match t=…,v1=… format → MALFORMED_SIGNATURE",
        "secret": SECRET,
        "timestamp": TS_RECENT,
        "body": PAYMENT_CONFIRMED_BODY.decode(),
        "signature_header": "v1=abc123",
        "expected": "error",
        "error_code": "MALFORMED_SIGNATURE",
    })

    # i03 — STALE_SIGNATURE: timestamp 600s in the past (default tolerance 300s)
    old_ts = TS_RECENT - 600
    sig_stale = _sign(SECRET, old_ts, PAYMENT_CONFIRMED_BODY)
    # Vectors use a fixed "now" offset field so test harness can fake time
    _write(invalid_dir / "i03_stale_signature.json", {
        "description": "Timestamp 600s old with 300s tolerance → STALE_SIGNATURE",
        "secret": SECRET,
        "timestamp": old_ts,
        "body": PAYMENT_CONFIRMED_BODY.decode(),
        "signature_header": sig_stale,
        "tolerance": 300,
        "fake_now": TS_RECENT,  # harness sets clock to this value
        "expected": "error",
        "error_code": "STALE_SIGNATURE",
    })

    # i04 — INVALID_SIGNATURE: v1 hex is wrong
    good_sig = _sign(SECRET, TS_RECENT, PAYMENT_CONFIRMED_BODY)
    # Flip the last hex character
    bad_v1 = good_sig[:-1] + ("0" if good_sig[-1] != "0" else "1")
    _write(invalid_dir / "i04_invalid_signature_v1.json", {
        "description": "v1 HMAC value corrupted → INVALID_SIGNATURE",
        "secret": SECRET,
        "timestamp": TS_RECENT,
        "body": PAYMENT_CONFIRMED_BODY.decode(),
        "signature_header": bad_v1,
        "expected": "error",
        "error_code": "INVALID_SIGNATURE",
    })

    # i05 — INVALID_SIGNATURE: wrong secret
    wrong_secret_sig = _sign("algvw_wrong_secret", TS_RECENT, PAYMENT_CONFIRMED_BODY)
    _write(invalid_dir / "i05_wrong_secret.json", {
        "description": "Signature computed with wrong secret → INVALID_SIGNATURE",
        "secret": SECRET,
        "timestamp": TS_RECENT,
        "body": PAYMENT_CONFIRMED_BODY.decode(),
        "signature_header": wrong_secret_sig,
        "expected": "error",
        "error_code": "INVALID_SIGNATURE",
    })

    # i06 — INVALID_SIGNATURE: body tampered after signing
    tampered_body = PAYMENT_CONFIRMED_BODY.decode().replace("1000000", "9999999").encode()
    sig_orig = _sign(SECRET, TS_RECENT, PAYMENT_CONFIRMED_BODY)
    _write(invalid_dir / "i06_tampered_body.json", {
        "description": "Body modified after signature was generated → INVALID_SIGNATURE",
        "secret": SECRET,
        "timestamp": TS_RECENT,
        "body": tampered_body.decode(),
        "signature_header": sig_orig,
        "expected": "error",
        "error_code": "INVALID_SIGNATURE",
    })

    # i07 — INVALID_PAYLOAD: body is not JSON
    not_json = b"not-json-at-all"
    sig7 = _sign(SECRET, TS_RECENT, not_json)
    _write(invalid_dir / "i07_invalid_payload_not_json.json", {
        "description": "Body is not valid JSON → INVALID_PAYLOAD",
        "secret": SECRET,
        "timestamp": TS_RECENT,
        "body": not_json.decode(),
        "signature_header": sig7,
        "expected": "error",
        "error_code": "INVALID_PAYLOAD",
    })

    # i08 — UNKNOWN_EVENT_TYPE: type field is not recognised
    unknown_event = json.dumps({
        "id": "evt_unk_001",
        "type": "refund.issued",
        "created": TS_RECENT,
        "api_version": "2024-01-01",
        "data": {},
    }, separators=(",", ":")).encode()
    sig8 = _sign(SECRET, TS_RECENT, unknown_event)
    _write(invalid_dir / "i08_unknown_event_type.json", {
        "description": "Event type not in known set → UNKNOWN_EVENT_TYPE",
        "secret": SECRET,
        "timestamp": TS_RECENT,
        "body": unknown_event.decode(),
        "signature_header": sig8,
        "expected": "error",
        "error_code": "UNKNOWN_EVENT_TYPE",
    })

    print(f"\nDone. 5 valid + 8 invalid = 13 vectors written.")


if __name__ == "__main__":
    generate()
