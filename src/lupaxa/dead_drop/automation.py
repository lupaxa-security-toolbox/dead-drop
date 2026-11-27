"""Planning, recipes, slots, challenges, and recovery audits."""

from __future__ import annotations

import hashlib
import json
import os
import tomllib
from pathlib import Path
from typing import Any

from lupaxa.dead_drop.carriers.api import capacity, detect_format, embed, extract
from lupaxa.dead_drop.carriers.base import EmbedOptions
from lupaxa.dead_drop.crypto.kdf import KdfParams
from lupaxa.dead_drop.errors import ArgumentError, CapacityError, IntegrityError
from lupaxa.dead_drop.limits import Limits
from lupaxa.dead_drop.services.conceal import CryptoChoices, DistributionChoices, distribute, hide_into, open_envelope, prepare_package, seal

STRATEGIES = ("capacity", "low-distortion", "spread", "fewest-files", "robustness", "balanced", "custom")
PATH_FIELDS = ("input.path", "carriers.directory", "output.directory")


def plan_payload(payload: Path, carriers: list[Path], *, strategy: str, distribution: DistributionChoices, limits: Limits, options: EmbedOptions) -> dict[str, Any]:
    """Choose carriers without modifying them."""
    if strategy not in STRATEGIES:
        raise ArgumentError(f"Unknown planning strategy {strategy!r}.")
    package = prepare_package(payload, None, limits)
    rows: list[dict[str, Any]] = []
    for carrier in carriers:
        try:
            held = capacity(carrier, "auto", options, limits)
        except Exception as exc:
            rows.append({"path": str(carrier), "usable": False, "reason": str(exc), "capacity_bytes": 0})
            continue
        rows.append(
            {
                "path": str(carrier),
                "format": detect_format(carrier),
                "capacity_bytes": held,
                "sha256": hashlib.sha256(carrier.read_bytes()).hexdigest(),
                "usable": held > 0,
            }
        )
    usable = [row for row in rows if row["usable"]]
    if strategy == "fewest-files":
        usable.sort(key=lambda row: row["capacity_bytes"], reverse=True)
    elif strategy == "spread":
        usable.sort(key=lambda row: row["capacity_bytes"])
    selected = usable[: max(distribution.data_shards + distribution.parity_shards, 1)]
    available = sum(row["capacity_bytes"] for row in selected)
    required = len(package) + 64
    errors = []
    if available < required:
        errors.append("Selected carriers do not have enough validated capacity.")
    return {
        "input_payload_bytes": payload.stat().st_size,
        "packaged_payload_bytes": len(package),
        "encrypted_payload_bytes": len(package) + 48,
        "required_embedded_capacity_bytes": required,
        "available_carrier_capacity_bytes": available,
        "selected_carriers": [row["path"] for row in selected],
        "selected_algorithms": ["auto" for _ in selected],
        "fragment_allocation": [{"carrier": row["path"], "capacity_bytes": row["capacity_bytes"]} for row in selected],
        "redundancy": {"data_shards": distribution.data_shards, "parity_shards": distribution.parity_shards},
        "expected_recovery_threshold": distribution.data_shards,
        "estimated_distortion": "low" if strategy == "low-distortion" else "depends on the selected pixel algorithms",
        "warnings": ["Planning did not modify any carrier."],
        "blocking_errors": errors,
        "carrier_hashes": {row["path"]: row.get("sha256", "") for row in selected},
        "payload_path": str(payload),
    }


def assert_plan_fresh(plan: dict[str, Any]) -> None:
    """Reject a plan whose carriers changed after it was saved."""
    for path, digest in plan.get("carrier_hashes", {}).items():
        current = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        if current != digest:
            raise IntegrityError(f"Plan is stale because {path} changed.")


def load_recipe(path: Path) -> dict[str, Any]:
    """Load a recipe and reject anything that is not declarative TOML."""
    try:
        with path.open("rb") as handle:
            loaded = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ArgumentError(f"Recipe is not valid TOML: {exc}") from exc
    recipe = loaded.get("recipe")
    if not isinstance(recipe, dict) or "operation" not in recipe:
        raise ArgumentError("Recipe must contain [recipe] with an operation.")
    if recipe["operation"] not in {"hide", "distribute", "reveal", "vault-create"}:
        raise ArgumentError(f"Unsupported recipe operation {recipe['operation']!r}.")
    text = path.read_text(encoding="utf-8")
    if "exec(" in text or "import " in text or "__" in text:
        raise ArgumentError("Recipes cannot contain executable Python.")
    _expand_paths(loaded)
    return loaded


def _expand_paths(table: dict[str, Any]) -> None:
    for section, key in (("input", "path"), ("carriers", "directory"), ("output", "directory")):
        node = table.get(section)
        if isinstance(node, dict) and isinstance(node.get(key), str):
            node[key] = os.path.expandvars(node[key]) if "${" in node[key] else node[key]


def execute_plan(path: Path, limits: Limits, *, password: str, output: Path, kdf: KdfParams | None = None) -> dict[str, Any]:
    """Revalidate a saved plan and embed it. A changed carrier is a hard failure."""
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert_plan_fresh(saved)
    if saved.get("blocking_errors"):
        raise CapacityError("The saved plan has blocking errors and was not executed.")
    carriers = [Path(item) for item in saved["selected_carriers"]]
    output.mkdir(parents=True, exist_ok=True)
    outputs = [output / carrier.name for carrier in carriers]
    redundancy = saved["redundancy"]
    result = distribute(
        carriers,
        outputs,
        prepare_package(Path(saved["payload_path"]), None, limits),
        choices=CryptoChoices(encrypt=True, password=password, kdf=kdf or KdfParams()),
        distribution=DistributionChoices(mode="erasure-coded", data_shards=int(redundancy["data_shards"]), parity_shards=int(redundancy["parity_shards"])),
        options=EmbedOptions(),
        limits=limits,
    )
    result.pop("package", None)
    return result


def read_slots(carrier: Path, limits: Limits) -> list[dict[str, Any]]:
    """Read a slot table. Slot names are management data and are not a concealment claim."""
    try:
        blob = extract(carrier, "auto", EmbedOptions(), limits)
        body = open_envelope(blob, CryptoChoices(encrypt=False), limits)
        loaded = json.loads(body)
    except Exception:
        return []
    if not isinstance(loaded, list):
        return []
    return [item for item in loaded if isinstance(item, dict) and "name" in item]


def write_slots(carrier: Path, output: Path, slots: list[dict[str, Any]], limits: Limits) -> None:
    """Embed an unencrypted slot table into a new carrier copy."""
    names = [item["name"] for item in slots]
    if len(names) != len(set(names)):
        raise ArgumentError("Slot names must be unique inside one carrier.")
    blob, _ident = seal(json.dumps(slots).encode("utf-8"), CryptoChoices(encrypt=False), limits)
    embed(carrier, output, blob, "auto", EmbedOptions(), limits)


def run_recipe(path: Path, limits: Limits, *, password: str, dry_run: bool, kdf: KdfParams | None = None) -> dict[str, Any]:
    """Validate and run one recipe."""
    recipe = load_recipe(path)
    operation = recipe["recipe"]["operation"]
    if dry_run:
        return {"operation": operation, "dry_run": True, "valid": True}
    payload = Path(recipe["input"]["path"])
    directory = Path(recipe["carriers"]["directory"])
    carriers = sorted(item for item in directory.iterdir() if item.is_file() and not item.name.startswith("."))
    output = Path(recipe["output"]["directory"])
    output.mkdir(parents=True, exist_ok=True)
    choices = CryptoChoices(
        encrypt=bool(recipe.get("security", {}).get("encrypt", True)),
        password=password,
        algorithm=recipe.get("security", {}).get("algorithm", "chacha20-poly1305"),
        compress=recipe.get("input", {}).get("compress", "none"),
        kdf=kdf or KdfParams(),
    )
    if operation == "hide":
        if not carriers:
            raise CapacityError("The recipe did not find any carriers.")
        return hide_into(carriers[0], output / carriers[0].name, prepare_package(payload, None, limits), choices=choices, options=EmbedOptions(), limits=limits)
    if operation != "distribute":
        raise ArgumentError(f"Recipe operation {operation!r} is valid but must be run with its own command.")
    dist = recipe.get("distribution", {})
    distribution = DistributionChoices(mode=dist.get("strategy", "erasure-coded"), data_shards=int(dist.get("data_shards", 1)), parity_shards=int(dist.get("parity_shards", 0)))
    outputs = [output / carrier.name for carrier in carriers[: distribution.data_shards + distribution.parity_shards]]
    chosen = carriers[: len(outputs)]
    if not chosen:
        raise CapacityError("The recipe did not find any carriers.")
    result = distribute(chosen, outputs, prepare_package(payload, None, limits), choices=choices, distribution=distribution, options=EmbedOptions(), limits=limits)
    result.pop("package", None)
    return result


def create_challenge(output: Path, *, difficulty: str, seed: str) -> dict[str, Any]:
    """Create a reproducible puzzle and store the solution only under `.private`."""
    if difficulty not in {"easy", "medium", "hard", "expert", "custom"}:
        raise ArgumentError(f"Unknown difficulty {difficulty!r}.")
    from PIL import Image

    from lupaxa.dead_drop.services.conceal import hide_into

    output.mkdir(parents=True, exist_ok=True)
    solution = hashlib.sha256(f"{difficulty}:{seed}".encode()).digest()
    commitment = hashlib.sha256(solution).hexdigest()
    private = output / ".private"
    private.mkdir(exist_ok=True)
    (private / "solution.bin").write_bytes(solution)
    os.chmod(private / "solution.bin", 0o600)
    password = f"{difficulty}-{seed}"
    (private / "password.txt").write_text(password + "\n", encoding="utf-8")
    os.chmod(private / "password.txt", 0o600)
    package = prepare_package(None, solution, Limits())
    choices = CryptoChoices(encrypt=True, password=password, kdf=KdfParams(time_cost=1, memory_kib=8, parallelism=1))

    def _hide_in_place(path: Path, algorithm: str) -> None:
        temporary = path.with_name(path.name + ".part")
        hide_into(path, temporary, package, choices=choices, options=EmbedOptions(), limits=Limits(), algorithm=algorithm)
        temporary.replace(path)

    carriers: list[str] = []
    if difficulty in {"easy", "custom"}:
        path = output / "carrier.png"
        Image.new("RGB", (96, 96), (20, 40, 60)).save(path)
        _hide_in_place(path, "png-lsb")
        carriers.append(path.name)
        clues = ["One PNG. Pixel LSB. The password is the difficulty, a hyphen, and the generation seed."]
    elif difficulty == "medium":
        paths = []
        for index in range(2):
            path = output / f"part-{index}.png"
            Image.new("RGB", (140, 140), (index, 30, 50)).save(path)
            paths.append(path)
        outs = [output / f"shared-{index}.png" for index in range(2)]
        distribute(paths, outs, package, choices=choices, distribution=DistributionChoices(data_shards=1, parity_shards=1), options=EmbedOptions(), limits=Limits())
        for path in paths:
            path.unlink()
        carriers.extend(path.name for path in outs)
        clues = ["Two PNG fragments. Either intact fragment is enough. Password shape matches the easy clue."]
    elif difficulty == "hard":
        path = output / "note.txt"
        path.write_text("A public note that is safe to read.\n", encoding="utf-8")
        _hide_in_place(path, "txt-zero-width")
        carriers.append(path.name)
        clues = ["The message is in the text file. The password is not in this file."]
    else:
        path = output / "diagram.svg"
        path.write_text("<svg xmlns='http://www.w3.org/2000/svg'><rect width='8' height='8'/></svg>", encoding="utf-8")
        _hide_in_place(path, "svg-metadata")
        carriers.append(path.name)
        clues = ["Inspect the document structure. The password is not published here."]
    public = {
        "id": hashlib.sha256(seed.encode()).hexdigest()[:16],
        "difficulty": difficulty,
        "solution_type": "bytes",
        "commitment": commitment,
        "carriers": carriers,
        "clues": clues,
        "generation": {"template": difficulty, "version": 1, "parameter_commitment": commitment},
    }
    (output / "challenge.json").write_text(json.dumps(public, indent=2) + "\n", encoding="utf-8")
    return public


def verify_challenge(directory: Path, answer: bytes) -> dict[str, Any]:
    """Check an answer against the public commitment."""
    public = json.loads((directory / "challenge.json").read_text(encoding="utf-8"))
    matches = hashlib.sha256(answer).hexdigest() == public["commitment"]
    return {"matches": matches, "commitment": public["commitment"]}


def audit_recovery(plan: dict[str, Any], *, mode: str) -> dict[str, Any]:
    """Report analytical recovery properties and label sampled results as samples."""
    data = int(plan["redundancy"]["data_shards"])
    parity = int(plan["redundancy"]["parity_shards"])
    analytical = {
        "kind": "analytical",
        "reconstruction_threshold": data,
        "tolerated_losses": parity,
        "note": "This holds only when each shard sits on a distinct carrier with enough capacity.",
    }
    return {"mode": mode, "analytical": analytical, "sampled": mode != "exhaustive", "passwords_included": False}
