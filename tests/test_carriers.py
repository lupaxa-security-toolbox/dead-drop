"""Round trips for every carrier family."""

from __future__ import annotations

import wave
import zipfile
from pathlib import Path

import pytest
from PIL import Image

from lupaxa.dead_drop.carriers.base import EmbedOptions
from lupaxa.dead_drop.crypto.kdf import KdfParams
from lupaxa.dead_drop.errors import AuthenticationError
from lupaxa.dead_drop.limits import Limits
from lupaxa.dead_drop.services.conceal import CryptoChoices, hide_into, prepare_package, reveal_from

FAST = KdfParams(time_cost=1, memory_kib=8, parallelism=1, hash_len=32)


def _choices() -> CryptoChoices:
    return CryptoChoices(encrypt=True, password="correct-horse-battery", kdf=FAST)


def test_bmp_wav_text_svg_zip(tmp_path: Path) -> None:
    image = tmp_path / "picture.bmp"
    Image.new("RGB", (80, 80), (8, 16, 24)).save(image, format="BMP")
    audio = tmp_path / "tone.wav"
    with wave.open(str(audio), "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(8000)
        handle.writeframes(b"\x00\x10" * 4000)
    text = tmp_path / "note.txt"
    text.write_text("A short carrier note.\n", encoding="utf-8")
    markup = tmp_path / "note.md"
    markup.write_text("# Note\n\nA markdown carrier.\n", encoding="utf-8")
    drawing = tmp_path / "drawing.svg"
    drawing.write_text("<svg xmlns='http://www.w3.org/2000/svg'><rect width='10' height='10'/></svg>", encoding="utf-8")
    archive = tmp_path / "files.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("readme.txt", "ordinary archive member")
    package = prepare_package(None, b"carrier-payload", Limits())
    for carrier in (image, audio, text, markup, drawing, archive):
        original = carrier.read_bytes()
        output = tmp_path / f"out-{carrier.name}"
        report = hide_into(carrier, output, package, choices=_choices(), options=EmbedOptions(), limits=Limits())
        assert report["verified"] is True
        assert carrier.read_bytes() == original
        revealed = reveal_from(output, choices=_choices(), options=EmbedOptions(), limits=Limits())
        assert revealed["verified"] is True
        with pytest.raises(AuthenticationError):
            reveal_from(
                output,
                choices=CryptoChoices(encrypt=True, password="wrong-password-value", kdf=FAST),
                options=EmbedOptions(),
                limits=Limits(),
            )
