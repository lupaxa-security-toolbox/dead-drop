"""PCM WAV sample LSB embedding."""

from __future__ import annotations

import math
import wave
from pathlib import Path
from typing import Any

from lupaxa.dead_drop.carriers.base import EmbedOptions, EmbedReport, read_bits, usable_bytes, write_bits
from lupaxa.dead_drop.errors import IntegrityError, UnsupportedError

ALG_WAV_LSB = 5


def _open(path: Path) -> tuple[wave.Wave_read, bytes]:
    try:
        handle = wave.open(str(path), "rb")  # noqa: SIM115
    except wave.Error as exc:
        raise UnsupportedError(f"Unsupported WAV file: {exc}") from exc
    if handle.getcomptype() != "NONE":
        handle.close()
        raise UnsupportedError("Compressed WAV files are not supported.")
    width = handle.getsampwidth()
    if width not in {1, 2, 3, 4}:
        handle.close()
        raise UnsupportedError(f"WAV sample width {width} is not a supported integer PCM width.")
    frames = handle.readframes(handle.getnframes())
    return handle, frames


def describe(path: Path) -> dict[str, Any]:
    """Return WAV layout details."""
    handle, frames = _open(path)
    try:
        return {
            "format": "wav",
            "channels": handle.getnchannels(),
            "sample_width": handle.getsampwidth(),
            "frame_rate": handle.getframerate(),
            "frames": handle.getnframes(),
            "payload_bytes": len(frames),
        }
    finally:
        handle.close()


def _selected(channels: int, options: EmbedOptions) -> tuple[int, ...]:
    if options.channels == ("r", "g", "b"):
        return tuple(range(channels))
    selected: list[int] = []
    for name in options.channels:
        if name.isdigit():
            index = int(name)
        elif name.lower() in {"m", "mono", "l", "left"}:
            index = 0
        elif name.lower() in {"right", "r"} and channels > 1:
            index = 1
        else:
            raise UnsupportedError(f"Unknown WAV channel {name!r}. Use indexes such as 0 or 1.")
        if index < 0 or index >= channels:
            raise UnsupportedError(f"WAV channel {index} is outside 0..{channels - 1}.")
        selected.append(index)
    return tuple(dict.fromkeys(selected))


def capacity_bits(path: Path, options: EmbedOptions) -> int:
    """One bit per selected sample, in the least significant bit only."""
    info = describe(path)
    return int(info["frames"]) * len(_selected(int(info["channels"]), options))


def _sample_offset(frame: int, channel: int, channels: int, width: int) -> int:
    return (frame * channels + channel) * width


def embed_lsb(source: Path, destination: Path, payload: bytes, options: EmbedOptions) -> EmbedReport:
    """Embed into the least significant bit of integer PCM samples."""
    handle, frames = _open(source)
    info = {
        "channels": handle.getnchannels(),
        "width": handle.getsampwidth(),
        "rate": handle.getframerate(),
        "frames": handle.getnframes(),
    }
    handle.close()
    selected = _selected(info["channels"], options)
    total = info["frames"] * len(selected)
    data = bytearray(frames)
    changed = 0

    def set_bit(index: int, bit: int) -> None:
        nonlocal changed
        if options.placement == "distributed":
            channel = selected[index // info["frames"]]
            frame = index % info["frames"]
        else:
            frame = index // len(selected)
            channel = selected[index % len(selected)]
        offset = _sample_offset(frame, channel, info["channels"], info["width"])
        updated = (data[offset] & ~1) | (bit & 1)
        if updated != data[offset]:
            changed += 1
            data[offset] = updated

    write_bits(total, options, payload, set_bit)
    with wave.open(str(destination), "wb") as output:
        output.setnchannels(info["channels"])
        output.setsampwidth(info["width"])
        output.setframerate(info["rate"])
        output.writeframes(bytes(data))
    describe(destination)
    metrics = _snr(frames, bytes(data))
    warnings = list(options.warnings)
    return EmbedReport(
        "wav-lsb", "covert", len(payload), usable_bytes(total, options), changed, metrics, warnings, str(destination)
    )


def extract_lsb(path: Path, size: int, options: EmbedOptions) -> bytes:
    """Read LSB payload bytes from a WAV file."""
    handle, frames = _open(path)
    info = {"channels": handle.getnchannels(), "width": handle.getsampwidth(), "frames": handle.getnframes()}
    handle.close()
    selected = _selected(info["channels"], options)
    total = info["frames"] * len(selected)

    def get_bit(index: int) -> int:
        if options.placement == "distributed":
            channel = selected[index // info["frames"]]
            frame = index % info["frames"]
        else:
            frame = index // len(selected)
            channel = selected[index % len(selected)]
        offset = _sample_offset(frame, channel, info["channels"], info["width"])
        return frames[offset] & 1

    data, _resolved = read_bits(total, options, size, get_bit)
    return data


def _snr(before: bytes, after: bytes) -> dict[str, Any]:
    if len(before) != len(after) or not before:
        raise IntegrityError("WAV rewrite changed the sample byte count.")
    noise = [(left - right) ** 2 for left, right in zip(before, after, strict=True)]
    signal = [byte * byte for byte in before]
    signal_power = sum(signal) / len(signal)
    noise_power = sum(noise) / len(noise)
    snr = None if noise_power == 0 else float(10 * math.log10(signal_power / noise_power)) if signal_power else 0.0
    return {
        "snr_db": snr,
        "changed_samples": sum(1 for left, right in zip(before, after, strict=True) if left != right),
        "mean_absolute_difference": sum(abs(left - right) for left, right in zip(before, after, strict=True))
        / len(before),
    }
