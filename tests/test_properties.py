"""Property checks for envelopes, paths, and configuration."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from lupaxa.dead_drop.errors import FilesystemError
from lupaxa.dead_drop.paths import safe_join
from lupaxa.dead_drop.payload.envelope import build_envelope, parse_envelope
from lupaxa.dead_drop.redact import RedactFilter, register_secret


@settings(max_examples=25)
@given(st.binary(max_size=128))
def test_unencrypted_envelope_round_trip(payload: bytes) -> None:
    blob = build_envelope(
        envelope_type=1,
        algorithm_id=0,
        payload_id=b"\x01" * 16,
        plaintext=payload,
        encryption="none",
        max_plain_bytes=10_000,
    )
    parsed = parse_envelope(blob, key=None, max_plain_bytes=10_000)
    assert parsed.body == payload


def test_path_escape_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(FilesystemError):
        safe_join(tmp_path, "../outside.txt")


def test_logs_do_not_keep_registered_secrets() -> None:
    register_secret("correct-horse-battery")
    record = logging.LogRecord("dead_drop", logging.INFO, __file__, 1, "password=correct-horse-battery", (), None)
    RedactFilter().filter(record)
    assert "correct-horse-battery" not in record.msg
