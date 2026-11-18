"""SVG metadata embedding using a hardened XML parser."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any, cast
from xml.etree.ElementTree import Element, SubElement, tostring

from defusedxml.ElementTree import fromstring

from lupaxa.dead_drop.carriers.base import EmbedOptions, EmbedReport
from lupaxa.dead_drop.errors import IntegrityError, UnsupportedError

ALG_SVG = 12
NS = "urn:dead-drop:1"
DANGEROUS_TAGS = {"script", "foreignobject", "handler", "iframe", "embed", "set", "animate"}
DANGEROUS_PREFIXES = ("on",)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _parse(path: Path) -> Element:
    data = path.read_bytes()
    lowered = data.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise UnsupportedError("SVG documents with a doctype or entity declaration are rejected.")
    try:
        root = fromstring(data)
    except Exception as exc:
        raise IntegrityError(f"SVG document is not well-formed: {exc}") from exc
    if _local(root.tag) != "svg":
        raise UnsupportedError("Document root is not svg.")
    for element in root.iter():
        if _local(element.tag) in DANGEROUS_TAGS:
            raise UnsupportedError(f"SVG element <{_local(element.tag)}> is rejected.")
        for attribute, value in element.attrib.items():
            name = _local(attribute)
            if name.startswith(DANGEROUS_PREFIXES):
                raise UnsupportedError(f"SVG attribute {name!r} is rejected.")
            if name in {"href", "xlink:href"} and str(value).lower().startswith("javascript:"):
                raise UnsupportedError("SVG javascript links are rejected.")
    return cast(Element, root)


def validate_svg(path: Path) -> dict[str, Any]:
    """Parse an SVG and report structural facts."""
    root = _parse(path)
    return {"format": "svg", "root": _local(root.tag), "elements": sum(1 for _ in root.iter())}


def embed(source: Path, destination: Path, payload: bytes, options: EmbedOptions) -> EmbedReport:
    """Embed a payload in an SVG metadata element. This is structured concealment, not pixel steganography."""
    root = _parse(source)
    metadata = None
    for child in list(root):
        if _local(child.tag) == "metadata":
            metadata = child
            break
    if metadata is None:
        metadata = SubElement(root, "metadata")
    for child in list(metadata):
        if _local(child.tag) == "payload" and child.tag.startswith(f"{{{NS}}}"):
            metadata.remove(child)
    node = SubElement(metadata, f"{{{NS}}}payload")
    node.text = base64.b64encode(payload).decode("ascii")
    destination.write_bytes(tostring(root, encoding="utf-8", xml_declaration=True))
    extracted = extract(destination)
    if extracted != payload:
        destination.unlink(missing_ok=True)
        raise IntegrityError("SVG embedding failed its recovery check.")
    return EmbedReport(
        "svg-metadata",
        "structured",
        len(payload),
        options.max_bytes or 16 * 1024 * 1024,
        1,
        {"mse": None, "psnr": None, "note": "visible geometry was not modified"},
        ["SVG metadata embedding is structured concealment. It is visible in the XML.", *options.warnings],
        str(destination),
    )


def extract(path: Path) -> bytes:
    """Read the metadata payload from an SVG document."""
    root = _parse(path)
    for element in root.iter():
        if _local(element.tag) == "payload" and element.tag.startswith(f"{{{NS}}}") and element.text:
            try:
                return base64.b64decode(element.text.encode("ascii"), validate=True)
            except Exception as exc:
                raise IntegrityError("SVG payload is not valid base64.") from exc
    raise IntegrityError("SVG document has no dead-drop metadata payload.")
