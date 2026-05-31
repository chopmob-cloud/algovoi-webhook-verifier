"""Typed error codes for AlgoVoi webhook verification failures."""

from __future__ import annotations

from typing import Literal

ERROR_CODES = frozenset({
    "MISSING_SIGNATURE",
    "MALFORMED_SIGNATURE",
    "STALE_SIGNATURE",
    "INVALID_SIGNATURE",
    "INVALID_PAYLOAD",
    "UNKNOWN_EVENT_TYPE",
})

ErrorCode = Literal[
    "MISSING_SIGNATURE",
    "MALFORMED_SIGNATURE",
    "STALE_SIGNATURE",
    "INVALID_SIGNATURE",
    "INVALID_PAYLOAD",
    "UNKNOWN_EVENT_TYPE",
]


class WebhookVerificationError(Exception):
    """Raised when webhook signature verification fails.

    Attributes:
        code:    One of the six ``ERROR_CODES`` values.
        message: Human-readable description.
    """

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code: ErrorCode = code
        self.message: str = message

    def __repr__(self) -> str:
        return f"WebhookVerificationError(code={self.code!r}, message={self.message!r})"
