"""CLI and library tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from PIL import Image
from typer.testing import CliRunner

from lupaxa.dead_drop.carriers.base import EmbedOptions
from lupaxa.dead_drop.cli.main import app
from lupaxa.dead_drop.crypto.kdf import KdfParams
from lupaxa.dead_drop.crypto.shamir import combine_shares, split_secret
from lupaxa.dead_drop.errors import AuthenticationError, IntegrityError
from lupaxa.dead_drop.limits import Limits
from lupaxa.dead_drop.services.conceal import CryptoChoices, DistributionChoices, distribute, hide_into, prepare_package, recover_from, reveal_from
from lupaxa.dead_drop.version import __version__, get_version

runner = CliRunner()
FAST = KdfParams(time_cost=1, memory_kib=8, parallelism=1, hash_len=32)


def test_version_is_semantic() -> None:
    import re

    assert get_version() == __version__
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", __version__)


def test_help_lists_required_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for name in ["hide", "reveal", "distribute", "recover", "plan", "vault", "challenge", "recipe", "interactive"]:
        assert name in result.stdout


def test_png_round_trip(tmp_path: Path) -> None:
    image = tmp_path / "in.png"
    Image.new("RGB", (96, 96), (12, 24, 36)).save(image)
    original = image.read_bytes()
    payload = prepare_package(None, b"payload", Limits())
    choices = CryptoChoices(encrypt=True, password="correct-horse-battery", kdf=FAST)
    output = tmp_path / "out.png"
    report = hide_into(image, output, payload, choices=choices, options=EmbedOptions(), limits=Limits())
    assert report["verified"] is True
    assert image.read_bytes() == original
    revealed = reveal_from(output, choices=choices, options=EmbedOptions(), limits=Limits())
    assert revealed["verified"] is True
    with pytest.raises(AuthenticationError):
        reveal_from(output, choices=CryptoChoices(encrypt=True, password="wrong-password-value", kdf=FAST), options=EmbedOptions(), limits=Limits())


def test_erasure_and_shamir(tmp_path: Path) -> None:
    secret = b"0123456789abcdef0123456789abcdef"
    shares = split_secret(secret, shares=5, threshold=3)
    assert combine_shares([shares[0], shares[2], shares[4]]) == secret
    with pytest.raises(IntegrityError):
        combine_shares(shares[:2])
    carriers = []
    for index in range(3):
        path = tmp_path / f"{index}.png"
        Image.new("RGB", (140, 140), (index, index, index)).save(path)
        carriers.append(path)
    package = prepare_package(None, b"distributed", Limits())
    outs = [tmp_path / f"out-{index}.png" for index in range(3)]
    choices = CryptoChoices(encrypt=True, password="correct-horse-battery", kdf=FAST)
    distribute(carriers, outs, package, choices=choices, distribution=DistributionChoices(data_shards=2, parity_shards=1), options=EmbedOptions(), limits=Limits())
    recovered = recover_from(outs[:2], choices=choices, options=EmbedOptions(), limits=Limits())
    assert recovered["package"] == package


def test_cli_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def test_plan_does_not_modify(tmp_path: Path) -> None:
    image = tmp_path / "a.png"
    Image.new("RGB", (32, 32), "white").save(image)
    payload = tmp_path / "secret.txt"
    payload.write_text("hello", encoding="utf-8")
    before = image.read_bytes()
    result = runner.invoke(app, ["--json", "plan", str(payload), "--carriers", str(tmp_path), "--optimise", "balanced"])
    assert result.exit_code == 0
    body = json.loads(result.stdout)
    assert body["success"] is True
    assert image.read_bytes() == before
