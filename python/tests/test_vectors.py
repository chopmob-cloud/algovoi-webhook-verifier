"""Cross-validation vector tests for algovoi_webhook_verifier."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from algovoi_webhook_verifier import WebhookVerificationError, verify_webhook

VECTORS_ROOT = Path(__file__).parent.parent.parent / "vectors"


def _load_vectors(subdir: str):
    d = VECTORS_ROOT / subdir
    if not d.exists():
        pytest.skip(f"Vector directory not found: {d}")
    return sorted(d.glob("*.json"))


# --------------------------------------------------------------------------- #
# Valid vectors — must all succeed                                             #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("fixture_path", _load_vectors("valid"))
def test_valid_vector(fixture_path):
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    body = fixture["body"].encode("utf-8")
    event = verify_webhook(
        payload=body,
        secret=fixture["secret"],
        signature_header=fixture["signature_header"],
        tolerance=0,  # vectors use fixed timestamps — disable staleness check
    )
    assert event["type"] == "payment.confirmed"


# --------------------------------------------------------------------------- #
# Invalid vectors — must raise with matching error_code                       #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("fixture_path", _load_vectors("invalid"))
def test_invalid_vector(fixture_path):
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    body = fixture["body"].encode("utf-8")
    tolerance = fixture.get("tolerance", 0)
    fake_now = fixture.get("fake_now")

    expected_code = fixture["error_code"]

    def _run():
        verify_webhook(
            payload=body,
            secret=fixture["secret"],
            signature_header=fixture["signature_header"],
            tolerance=tolerance,
        )

    with pytest.raises(WebhookVerificationError) as exc_info:
        if fake_now is not None:
            with patch("algovoi_webhook_verifier.verify.time") as mock_time:
                mock_time.time.return_value = fake_now
                _run()
        else:
            _run()

    assert exc_info.value.code == expected_code, (
        f"Vector {fixture_path.name}: expected error code {expected_code!r}, "
        f"got {exc_info.value.code!r}"
    )
