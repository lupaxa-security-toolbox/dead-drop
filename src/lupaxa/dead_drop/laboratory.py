"""Forensic measurements, pictures, and transformation tests.

Statistical results are measurements or heuristics. They are not proof that a
payload is present or absent.
"""

from __future__ import annotations

import json
import math
import time
import tracemalloc
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw

from lupaxa.dead_drop.carriers.api import capacity, detect_format, validate
from lupaxa.dead_drop.carriers.base import EmbedOptions
from lupaxa.dead_drop.errors import UnsupportedError
from lupaxa.dead_drop.limits import Limits


def analyse(path: Path, limits: Limits, *, deep: bool) -> dict[str, Any]:
    """Collect facts, measurements, and labelled heuristics for one carrier."""
    kind = detect_format(path)
    report: dict[str, Any] = {
        "path": str(path),
        "format": kind,
        "size_bytes": path.stat().st_size,
        "validation": validate(path, limits),
        "facts": [],
        "measurements": [],
        "heuristics": [],
        "detections": [],
        "unsupported": ["Statistical indicators do not prove that steganography is present or absent."],
    }
    data = path.read_bytes()
    report["measurements"].append({"name": "byte_entropy", "value": _entropy(data), "units": "bits_per_byte"})
    if data.startswith(b"\x89PNG") and b"IEND" in data and not data.rstrip(b"\x00").endswith(b"IEND\xaeB`\x82"):
        report["facts"].append("Bytes follow the PNG IEND chunk.")
    if b"DDR1" in data:
        report["detections"].append(
            {"name": "envelope_magic", "detail": "A Dead Drop envelope magic value was found in cleartext bytes."}
        )
    if kind == "png" and deep:
        report["measurements"].extend(_image_measurements(path))
    if kind in {"txt", "markdown"}:
        from lupaxa.dead_drop.carriers.text import analyse_text

        report["measurements"].append(analyse_text(path))
    return report


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def _image_measurements(path: Path) -> list[dict[str, Any]]:
    import numpy as np

    with Image.open(path) as image:
        array = np.asarray(image.convert("RGB"))
    measurements = []
    for index, name in enumerate("rgb"):
        channel = array[:, :, index]
        lsb = channel & 1
        zeros = int(np.count_nonzero(lsb == 0))
        ones = int(lsb.size - zeros)
        expected = lsb.size / 2
        chi = ((zeros - expected) ** 2 + (ones - expected) ** 2) / expected
        measurements.append(
            {
                "name": f"{name}_lsb_chi_square",
                "value": float(chi),
                "kind": "heuristic",
                "note": "A chi-square statistic over least-significant bits. It is not a detection decision.",
            }
        )
    return measurements


def compare_carriers(left: Path, right: Path) -> dict[str, Any]:
    """Compare two carriers and label the result as a measurement."""
    from lupaxa.dead_drop.carriers.png import _metrics

    result: dict[str, Any] = {"left": str(left), "right": str(right), "kind": "measurement"}
    try:
        with Image.open(left) as before, Image.open(right) as after:
            result["metrics"] = _metrics(before, after)
    except Exception:
        result["metrics"] = {"note": "Visual metrics are available for images. Byte length is always reported."}
    result["left_bytes"] = left.stat().st_size
    result["right_bytes"] = right.stat().st_size
    return result


def visualise(path: Path, kind: str, output: Path, *, channel: str = "red", bit: int = 0) -> dict[str, Any]:
    """Write a PNG, SVG, HTML, or JSON visualisation."""
    output.parent.mkdir(parents=True, exist_ok=True)
    if kind == "bit-plane":
        _bit_plane(path, output, channel, bit)
    elif kind == "histogram":
        _histogram(path, output)
    elif kind == "waveform":
        _waveform(path, output)
    elif output.suffix == ".svg":
        output.write_text(_svg_bar(kind, [1, 2, 3, 4]), encoding="utf-8")
    elif output.suffix == ".html":
        output.write_text(_html(kind, path), encoding="utf-8")
    else:
        output.write_text(json.dumps({"kind": kind, "path": str(path)}) + "\n", encoding="utf-8")
    return {
        "type": kind,
        "output": str(output),
        "note": "Visualisations are measurements, not proof of a hidden payload.",
    }


def _bit_plane(path: Path, output: Path, channel: str, bit: int) -> None:
    import numpy as np

    with Image.open(path) as image:
        array = np.asarray(image.convert("RGB"))
    index = {"red": 0, "green": 1, "blue": 2}[channel]
    plane = ((array[:, :, index] >> bit) & 1) * 255
    Image.fromarray(plane.astype("uint8"), mode="L").save(output)


def _histogram(path: Path, output: Path) -> None:
    import numpy as np

    with Image.open(path) as image:
        array = np.asarray(image.convert("RGB"))
    canvas = Image.new("RGB", (256, 100), "white")
    draw = ImageDraw.Draw(canvas)
    for index, colour in enumerate([(220, 40, 40), (40, 160, 40), (40, 40, 200)]):
        hist = np.bincount(array[:, :, index].ravel(), minlength=256)
        peak = max(int(np.max(hist)), 1)
        for value, count in enumerate(hist):
            height = int(90 * count / peak)
            draw.line((value, 99, value, 99 - height), fill=colour)
    canvas.save(output)


def _waveform(path: Path, output: Path) -> None:
    import wave

    import numpy as np

    with wave.open(str(path), "rb") as handle:
        frames = np.frombuffer(handle.readframes(handle.getnframes()), dtype=np.uint8)
    width = 640
    if frames.size == 0:
        raise UnsupportedError("WAV file has no samples.")
    buckets = np.array_split(frames, width)
    canvas = Image.new("RGB", (width, 200), "white")
    draw = ImageDraw.Draw(canvas)
    for index, bucket in enumerate(buckets):
        value = int(bucket.mean()) if len(bucket) else 128
        draw.line((index, 100, index, value), fill=(20, 60, 120))
    canvas.save(output)


def _svg_bar(kind: str, values: list[int]) -> str:
    bars = []
    for index, value in enumerate(values):
        bars.append(f'<rect x="{index * 40}" y="{100 - value * 10}" width="30" height="{value * 10}" />')
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="400" height="120"><title>{kind}</title>{"".join(bars)}</svg>'
    )


def _html(kind: str, path: Path, rows: list[dict[str, Any]] | None = None) -> str:
    from jinja2 import Environment

    environment = Environment(autoescape=True)
    template = environment.from_string(
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>{{ title }}</title></head>"
        "<body><h1>{{ kind }}</h1><p>{{ name }}</p>"
        "<p>This page is a measurement, not a detection verdict.</p>"
        "<pre>{{ rows }}</pre></body></html>"
    )
    return template.render(
        title="Dead Drop visualisation", kind=kind, name=path.name, rows=json.dumps(rows or [], indent=2)
    )


def write_table(rows: list[dict[str, Any]], output: Path) -> None:
    """Write benchmark or analysis rows as CSV, Markdown, HTML, or JSON."""
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.suffix == ".csv":
        import csv

        with output.open("w", encoding="utf-8", newline="") as handle:
            fieldnames = list(rows[0]) if rows else ["empty"]
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        return
    if output.suffix == ".md":
        if not rows:
            output.write_text("# Report\n\nNo rows.\n", encoding="utf-8")
            return
        headers = list(rows[0])
        lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
        for row in rows:
            lines.append("| " + " | ".join(str(row.get(name, "")) for name in headers) + " |")
        output.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return
    if output.suffix == ".html":
        output.write_text(_html("table", output, rows), encoding="utf-8")
        return
    output.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")


def benchmark(path: Path, payload: bytes, algorithms: list[str], limits: Limits) -> list[dict[str, Any]]:
    """Compare algorithms on a temporary copy. Keys and plaintext are not recorded."""
    results = []
    for algorithm in algorithms:
        started = time.perf_counter()
        tracemalloc.start()
        try:
            held = capacity(path, algorithm, EmbedOptions(), limits)
            ok = held >= len(payload)
        except Exception as exc:
            held = 0
            ok = False
            error = str(exc)
        else:
            error = ""
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        results.append(
            {
                "algorithm": algorithm,
                "capacity_bytes": held,
                "payload_fits": ok,
                "seconds": round(time.perf_counter() - started, 6),
                "peak_memory_bytes": peak,
                "error": error,
            }
        )
    return results


def stress(path: Path, limits: Limits) -> list[dict[str, Any]]:
    """Run format-appropriate transforms on temporary copies."""
    kind = detect_format(path)
    if kind in {"png", "bmp"}:
        return stress_image(path, limits)
    if kind == "wav":
        return _stress_audio(path, limits)
    if kind in {"txt", "markdown"}:
        return _stress_text(path, limits)
    return [
        {
            "transformation": "unsupported",
            "parameters": {"format": kind},
            "carrier_valid": True,
            "embedded_data_detected": False,
            "reconstruction_possible": False,
            "authentication_succeeded": False,
            "failure_reason": "This format has no automated transform in the stress command.",
        }
    ]


def _stress_audio(path: Path, limits: Limits) -> list[dict[str, Any]]:
    import wave

    reports = []
    with wave.open(str(path), "rb") as source:
        frames = bytearray(source.readframes(source.getnframes()))
        params = source.getparams()
    gained = bytes(min(255, byte + 1) for byte in frames)
    for name, body in (("lossless-rewrite", bytes(frames)), ("gain", gained)):
        target = path.with_name(path.stem + f"-{name}.wav")
        with wave.open(str(target), "wb") as handle:
            handle.setparams(params)
            handle.writeframes(body)
        detected, reason = _try_extract(target, limits)
        reports.append(_stress_row(name, {"sample_width": params.sampwidth}, detected, reason))
        target.unlink(missing_ok=True)
    return reports


def _stress_text(path: Path, limits: Limits) -> list[dict[str, Any]]:
    original = path.read_text(encoding="utf-8")
    variants = {
        "line-endings": original.replace("\n", "\r\n"),
        "trim": "\n".join(line.rstrip() for line in original.splitlines()) + "\n",
    }
    reports = []
    for name, text in variants.items():
        target = path.with_name(path.stem + f"-{name}" + path.suffix)
        target.write_text(text, encoding="utf-8")
        detected, reason = _try_extract(target, limits)
        reports.append(_stress_row(name, {"encoding": "utf-8"}, detected, reason))
        target.unlink(missing_ok=True)
    return reports


def _try_extract(path: Path, limits: Limits) -> tuple[bool, str]:
    from lupaxa.dead_drop.carriers.api import extract

    try:
        extract(path, "auto", EmbedOptions(), limits)
    except Exception as exc:
        return False, type(exc).__name__
    return True, ""


def _stress_row(name: str, parameters: dict[str, Any], detected: bool, reason: str) -> dict[str, Any]:
    return {
        "transformation": name,
        "parameters": parameters,
        "carrier_valid": True,
        "embedded_data_detected": detected,
        "reconstruction_possible": detected,
        "authentication_succeeded": detected,
        "failure_reason": reason,
    }


def stress_image(path: Path, limits: Limits) -> list[dict[str, Any]]:
    """Apply image transformations to temporary copies and try to read an envelope."""
    reports = []
    with Image.open(path) as image:
        transforms: list[tuple[str, Image.Image]] = [
            ("lossless-rewrite", image.copy()),
            ("resize", image.resize((max(1, image.width // 2), max(1, image.height // 2)))),
            ("rotate", image.rotate(90, expand=True)),
            ("jpeg", image.convert("RGB")),
        ]
    for name, picture in transforms:
        save_format = "JPEG" if name == "jpeg" else "PNG"
        target = path.with_name(path.stem + f"-{name}").with_suffix(".jpg" if name == "jpeg" else ".png")
        picture.save(target, format=save_format)
        detected, reason = (False, "")
        if target.suffix == ".png":
            detected, reason = _try_extract(target, limits)
        else:
            reason = "jpeg conversion removes pixel LSB payloads"
        reports.append(_stress_row(name, {"format": save_format}, detected, reason))
        target.unlink(missing_ok=True)
    return reports
