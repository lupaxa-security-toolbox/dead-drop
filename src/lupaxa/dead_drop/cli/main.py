"""Dead Drop command-line interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import typer

from lupaxa.dead_drop import __version__
from lupaxa.dead_drop.automation import (
    audit_recovery,
    create_challenge,
    execute_plan,
    load_recipe,
    plan_payload,
    read_slots,
    run_recipe,
    verify_challenge,
    write_slots,
)
from lupaxa.dead_drop.carriers.api import algorithm_catalogue, detect_format, validate
from lupaxa.dead_drop.carriers.api import capacity as measure_capacity
from lupaxa.dead_drop.carriers.base import EmbedOptions
from lupaxa.dead_drop.config import load_config
from lupaxa.dead_drop.crypto.kdf import KdfParams
from lupaxa.dead_drop.crypto.keys import prompt_password, read_password_file, write_key_file
from lupaxa.dead_drop.crypto.shamir import combine_shares, parse_share, split_secret
from lupaxa.dead_drop.errors import DeadDropError, PartialBatchError
from lupaxa.dead_drop.history import read_history, record_history
from lupaxa.dead_drop.laboratory import analyse as analyse_file
from lupaxa.dead_drop.laboratory import (
    benchmark,
    compare_carriers,
    stress,
    write_table,
)
from lupaxa.dead_drop.laboratory import (
    visualise as render_visual,
)
from lupaxa.dead_drop.limits import Limits
from lupaxa.dead_drop.redact import configure_logging
from lupaxa.dead_drop.result import Result
from lupaxa.dead_drop.services.conceal import (
    CryptoChoices,
    DistributionChoices,
    hide_into,
    prepare_package,
    recover_from,
    reveal_from,
)
from lupaxa.dead_drop.services.conceal import (
    distribute as distribute_payload,
)
from lupaxa.dead_drop.vault.ops import (
    backup,
    compact,
    copy_path,
    destroy,
    find,
    listing,
    mkdir,
    move,
    rebalance,
    remove,
    repair_plan,
    restore_backup,
    restore_snapshot,
    snapshot,
    tree_lines,
)
from lupaxa.dead_drop.vault.ops import (
    verify as verify_vault,
)
from lupaxa.dead_drop.vault.store import VaultSettings, create_vault, open_vault

app = typer.Typer(no_args_is_help=True, add_completion=False)
carriers_app = typer.Typer(no_args_is_help=True)
shares_app = typer.Typer(no_args_is_help=True)
algorithms_app = typer.Typer(no_args_is_help=True)
payload_app = typer.Typer(no_args_is_help=True)
slots_app = typer.Typer(no_args_is_help=True)
vault_app = typer.Typer(no_args_is_help=True)
challenge_app = typer.Typer(no_args_is_help=True)
audit_app = typer.Typer(no_args_is_help=True)
recipe_app = typer.Typer(no_args_is_help=True)
app.add_typer(carriers_app, name="carriers")
app.add_typer(shares_app, name="shares")
app.add_typer(algorithms_app, name="algorithms")
app.add_typer(payload_app, name="payload")
app.add_typer(slots_app, name="slots")
app.add_typer(vault_app, name="vault")
app.add_typer(challenge_app, name="challenge")
app.add_typer(audit_app, name="audit")
app.add_typer(recipe_app, name="recipe")


def _print_version(value: bool) -> None:
    """Print the version and leave before a subcommand is required."""
    if value:
        typer.echo(__version__)
        raise typer.Exit()


class State:
    """Options shared by every command."""

    def __init__(self) -> None:
        self.json = False
        self.quiet = False
        self.non_interactive = False
        self.dry_run = False
        self.force = False
        self.jobs = 1
        self.config_path: Path | None = None
        self.profile: str | None = None


def _state(ctx: typer.Context) -> State:
    if not isinstance(ctx.obj, State):
        ctx.obj = State()
    return ctx.obj


def _limits(ctx: typer.Context) -> Limits:
    state = _state(ctx)
    return load_config(explicit=state.config_path, profile=state.profile).limits()


def _kdf(ctx: typer.Context) -> KdfParams:
    config = load_config(explicit=_state(ctx).config_path, profile=_state(ctx).profile)
    return KdfParams(config.kdf_time_cost, config.kdf_memory_kib, config.kdf_parallelism, 32)


def _password(ctx: typer.Context, password_file: Path | None, *, confirm: bool = False) -> str:
    if password_file is not None:
        password, warning = read_password_file(password_file)
        typer.echo(warning, err=True)
        return password
    return prompt_password(confirm=confirm, non_interactive=_state(ctx).non_interactive)


def _emit(ctx: typer.Context, result: Result, started: float) -> None:
    record_history(
        enabled=True,
        command=result.command,
        status="ok" if result.success else "error",
        started=started,
        warnings=result.warnings,
        error_code=result.errors[0]["code"] if result.errors else None,
    )
    if _state(ctx).json:
        sys.stdout.write(result.to_json() + "\n")
    else:
        typer.echo(json.dumps(result.data, indent=2) if result.data else result.command)
        for warning in result.warnings:
            typer.echo(f"warning: {warning}", err=True)


def _fail(ctx: typer.Context, command: str, exc: DeadDropError) -> int:
    result = Result(command=command, success=False)
    result.add_error(exc.code, str(exc), exit_code=exc.exit_code)
    if _state(ctx).json:
        sys.stdout.write(result.to_json() + "\n")
    else:
        typer.echo(str(exc), err=True)
    return exc.exit_code


@app.callback()
def main_callback(
    ctx: typer.Context,
    config: Path | None = typer.Option(None, "--config", help="Load an explicit TOML configuration."),
    json_output: bool = typer.Option(False, "--json", is_flag=True, help="Emit a JSON result envelope."),
    quiet: bool = typer.Option(False, "--quiet", is_flag=True),
    verbose: bool = typer.Option(False, "--verbose", is_flag=True),
    debug: bool = typer.Option(False, "--debug", is_flag=True),
    no_colour: bool = typer.Option(False, "--no-colour", is_flag=True),
    non_interactive: bool = typer.Option(False, "--non-interactive", is_flag=True),
    dry_run: bool = typer.Option(False, "--dry-run", is_flag=True),
    force: bool = typer.Option(False, "--force", is_flag=True),
    jobs: int = typer.Option(1, "--jobs"),
    temp_dir: Path | None = typer.Option(None, "--temp-dir"),
    profile: str | None = typer.Option(None, "--profile"),
    version: bool = typer.Option(False, "--version", is_flag=True, is_eager=True, callback=_print_version),
) -> None:
    """Conceal, protect, distribute, analyse, and recover data in ordinary files."""
    if version:
        typer.echo(__version__)
        raise typer.Exit()
    state = State()
    state.json = json_output
    state.quiet = quiet
    state.non_interactive = non_interactive
    state.dry_run = dry_run
    state.force = force
    state.jobs = jobs
    state.config_path = config
    state.profile = profile
    ctx.obj = state
    level = 10 if debug else 20 if verbose else 40 if quiet else 30
    configure_logging(level)
    del no_colour, temp_dir


@app.command()
def hide(
    ctx: typer.Context,
    carrier: Path,
    payload: Path,
    output: Path = typer.Option(..., "--output"),
    algorithm: str = typer.Option("auto", "--algorithm"),
    password_file: Path | None = typer.Option(None, "--password-file"),
    no_encrypt: bool = typer.Option(False, "--no-encrypt", is_flag=True),
) -> None:
    """Hide a payload in a carrier and verify that it can be read back."""
    import time

    started = time.monotonic()
    try:
        choices = CryptoChoices(encrypt=not no_encrypt, kdf=_kdf(ctx))
        if choices.encrypt:
            choices.password = _password(ctx, password_file, confirm=True)
        if _state(ctx).dry_run:
            _emit(ctx, Result("hide", data={"dry_run": True, "output": str(output)}), started)
            return
        data = hide_into(
            carrier,
            output,
            prepare_package(payload, None, _limits(ctx)),
            choices=choices,
            options=EmbedOptions(force=_state(ctx).force),
            limits=_limits(ctx),
            algorithm=algorithm,
        )
        _emit(ctx, Result("hide", data=data, warnings=data.pop("warnings")), started)
    except DeadDropError as exc:
        raise typer.Exit(_fail(ctx, "hide", exc)) from exc


@app.command()
def reveal(
    ctx: typer.Context,
    carrier: Path,
    output: Path = typer.Option(..., "--output"),
    algorithm: str = typer.Option("auto", "--algorithm"),
    password_file: Path | None = typer.Option(None, "--password-file"),
) -> None:
    """Extract and authenticate a payload."""
    import time

    started = time.monotonic()
    try:
        choices = CryptoChoices(encrypt=True, password=_password(ctx, password_file), kdf=_kdf(ctx))
        output.mkdir(parents=True, exist_ok=True)
        data = reveal_from(
            carrier,
            choices=choices,
            options=EmbedOptions(),
            limits=_limits(ctx),
            algorithm=algorithm,
            destination=output,
        )
        _emit(ctx, Result("reveal", data=data), started)
    except DeadDropError as exc:
        raise typer.Exit(_fail(ctx, "reveal", exc)) from exc


@app.command()
def distribute(
    ctx: typer.Context,
    payload: Path,
    carriers: Path = typer.Option(..., "--carriers"),
    output: Path = typer.Option(..., "--output"),
    data_shards: int = typer.Option(2, "--data-shards"),
    parity_shards: int = typer.Option(1, "--parity-shards"),
    password_file: Path | None = typer.Option(None, "--password-file"),
) -> None:
    """Encrypt a payload and spread it across carriers."""
    import time

    started = time.monotonic()
    try:
        files = sorted(path for path in carriers.iterdir() if path.is_file())[: data_shards + parity_shards]
        output.mkdir(parents=True, exist_ok=True)
        outs = [output / path.name for path in files]
        result = distribute_payload(
            files,
            outs,
            prepare_package(payload, None, _limits(ctx)),
            choices=CryptoChoices(encrypt=True, password=_password(ctx, password_file, confirm=True), kdf=_kdf(ctx)),
            distribution=DistributionChoices(data_shards=data_shards, parity_shards=parity_shards),
            options=EmbedOptions(),
            limits=_limits(ctx),
        )
        result.pop("package", None)
        _emit(ctx, Result("distribute", data=result), started)
    except DeadDropError as exc:
        raise typer.Exit(_fail(ctx, "distribute", exc)) from exc


@app.command()
def recover(
    ctx: typer.Context,
    directory: Path,
    output: Path = typer.Option(..., "--output"),
    password_file: Path | None = typer.Option(None, "--password-file"),
) -> None:
    """Recover a payload by scanning a directory. No separate manifest is required."""
    import time

    started = time.monotonic()
    try:
        files = sorted(path for path in directory.iterdir() if path.is_file())
        found = recover_from(
            files,
            choices=CryptoChoices(encrypt=True, password=_password(ctx, password_file), kdf=_kdf(ctx)),
            options=EmbedOptions(),
            limits=_limits(ctx),
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        from lupaxa.dead_drop.payload.package import unpack_package

        unpack_package(found["package"], output if output.is_dir() else output.parent, limits=_limits(ctx))
        _emit(
            ctx,
            Result("recover", data={"verified": True, "fragments": found["fragments"], "output": str(output)}),
            started,
        )
    except DeadDropError as exc:
        raise typer.Exit(_fail(ctx, "recover", exc)) from exc


@app.command()
def plan(
    ctx: typer.Context,
    payload: Path,
    carriers: Path = typer.Option(..., "--carriers"),
    optimise: str = typer.Option("balanced", "--optimise"),
    save: Path | None = typer.Option(None, "--save"),
) -> None:
    """Plan an embedding. This command never modifies carriers."""
    import time

    started = time.monotonic()
    files = sorted(path for path in carriers.iterdir() if path.is_file())
    result = plan_payload(
        payload,
        files,
        strategy=optimise,
        distribution=DistributionChoices(),
        limits=_limits(ctx),
        options=EmbedOptions(),
    )
    if save:
        save.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    _emit(ctx, Result("plan", data=result, warnings=result["warnings"]), started)


@app.command()
def capacity(ctx: typer.Context, carrier: Path, algorithm: str = typer.Option("auto", "--algorithm")) -> None:
    """Report validated embedding capacity. File size is not used as a proxy."""
    import time

    started = time.monotonic()
    held = measure_capacity(carrier, algorithm, EmbedOptions(), _limits(ctx))
    _emit(
        ctx, Result("capacity", data={"bytes": held, "algorithm": algorithm, "format": detect_format(carrier)}), started
    )


@app.command()
def inspect(ctx: typer.Context, carrier: Path) -> None:
    """Inspect one carrier."""
    import time

    _emit(ctx, Result("inspect", data=validate(carrier, _limits(ctx))), time.monotonic())


@app.command()
def analyse(
    ctx: typer.Context,
    carrier: Path,
    deep: bool = typer.Option(False, "--deep", is_flag=True),
) -> None:
    """Analyse a carrier. Statistics are not presented as proof."""
    import time

    _emit(ctx, Result("analyse", data=analyse_file(carrier, _limits(ctx), deep=deep)), time.monotonic())


@app.command()
def compare(ctx: typer.Context, left: Path, right: Path) -> None:
    """Compare two carriers."""
    import time

    _emit(ctx, Result("compare", data=compare_carriers(left, right)), time.monotonic())


@app.command()
def visualise(
    ctx: typer.Context,
    carrier: Path,
    kind: str = typer.Option(..., "--type"),
    output: Path = typer.Option(..., "--output"),
    channel: str = typer.Option("red", "--channel"),
    bit: int = typer.Option(0, "--bit"),
) -> None:
    """Export a visualisation."""
    import time

    _emit(
        ctx, Result("visualise", data=render_visual(carrier, kind, output, channel=channel, bit=bit)), time.monotonic()
    )


@app.command("stress-test")
def stress_test(ctx: typer.Context, carrier: Path) -> None:
    """Run transformation tests on temporary copies."""
    import time

    _emit(ctx, Result("stress-test", data={"results": stress(carrier, _limits(ctx))}), time.monotonic())


@app.command()
def verify(
    ctx: typer.Context,
    carrier: Path,
    expected: Path,
    password_file: Path | None = typer.Option(None, "--password-file"),
) -> None:
    """Reveal a carrier and compare it with an expected file."""
    import time

    started = time.monotonic()
    try:
        found = reveal_from(
            carrier,
            choices=CryptoChoices(encrypt=True, password=_password(ctx, password_file), kdf=_kdf(ctx)),
            options=EmbedOptions(),
            limits=_limits(ctx),
        )
        from lupaxa.dead_drop.payload.package import package_path

        expected_package = package_path(expected, limits=_limits(ctx))
        # reveal_from without a destination returns a package hash.
        ok = found.get("package_sha256") == __import__("hashlib").sha256(expected_package).hexdigest()
        _emit(ctx, Result("verify", data={"matches": ok}), started)
    except DeadDropError as exc:
        raise typer.Exit(_fail(ctx, "verify", exc)) from exc


@carriers_app.command("scan")
def carriers_scan(ctx: typer.Context, directory: Path) -> None:
    """Scan a directory for supported carriers."""
    import time

    rows = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            rows.append(
                {
                    "path": str(path),
                    "format": detect_format(path),
                    "capacity_bytes": measure_capacity(path, "auto", EmbedOptions(), _limits(ctx)),
                }
            )
        except Exception as exc:
            rows.append({"path": str(path), "unsupported": str(exc)})
    _emit(ctx, Result("carriers scan", data={"carriers": rows}), time.monotonic())


@carriers_app.command("list")
def carriers_list(ctx: typer.Context, directory: Path) -> None:
    """List supported files in a directory."""
    carriers_scan(ctx, directory)


@carriers_app.command("inspect")
def carriers_inspect(ctx: typer.Context, carrier: Path) -> None:
    """Inspect one file from a collection."""
    inspect(ctx, carrier)


@carriers_app.command("validate")
def carriers_validate(ctx: typer.Context, carrier: Path) -> None:
    """Validate a carrier's structure."""
    inspect(ctx, carrier)


@shares_app.command("create")
def shares_create(
    ctx: typer.Context,
    secret: Path,
    shares: int = typer.Option(..., "--shares"),
    threshold: int = typer.Option(..., "--threshold"),
    output: Path = typer.Option(..., "--output"),
) -> None:
    """Split a key file into Shamir shares."""
    import time

    output.mkdir(parents=True, exist_ok=True)
    parts = split_secret(secret.read_bytes(), shares=shares, threshold=threshold)
    for index, share in enumerate(parts, start=1):
        (output / f"share-{index}.ddshare").write_bytes(share.serialise())
    _emit(
        ctx,
        Result("shares create", data={"shares": shares, "threshold": threshold, "output": str(output)}),
        time.monotonic(),
    )


@shares_app.command("inspect")
def shares_inspect(ctx: typer.Context, share: Path) -> None:
    """Describe a share without revealing its secret."""
    import time

    parsed = parse_share(share.read_bytes())
    _emit(
        ctx,
        Result(
            "shares inspect", data={"threshold": parsed.threshold, "index": parsed.index, "set_id": parsed.set_id.hex()}
        ),
        time.monotonic(),
    )


@shares_app.command("combine")
def shares_combine(ctx: typer.Context, directory: Path, output: Path = typer.Option(..., "--output")) -> None:
    """Reconstruct a secret from a share directory."""
    import time

    parts = [parse_share(path.read_bytes()) for path in sorted(directory.glob("*.ddshare"))]
    secret = combine_shares(parts)
    write_key_file(output, secret, force=_state(ctx).force) if output.suffix == ".key" else output.write_bytes(secret)
    _emit(ctx, Result("shares combine", data={"output": str(output), "verified": True}), time.monotonic())


@shares_app.command("verify")
def shares_verify(ctx: typer.Context, directory: Path) -> None:
    """Check that the shares reconstruct and agree."""
    import time

    parts = [parse_share(path.read_bytes()) for path in sorted(directory.glob("*.ddshare"))]
    combine_shares(parts)
    _emit(ctx, Result("shares verify", data={"verified": True, "shares": len(parts)}), time.monotonic())


@algorithms_app.command("list")
def algorithms_list(ctx: typer.Context) -> None:
    """List embedding algorithms."""
    import time

    _emit(ctx, Result("algorithms list", data={"algorithms": list(algorithm_catalogue())}), time.monotonic())


@algorithms_app.command("info")
def algorithms_info(ctx: typer.Context, identifier: str) -> None:
    """Show one algorithm's declared properties."""
    import time

    info = algorithm_catalogue()[identifier]
    _emit(ctx, Result("algorithms info", data=info.to_dict()), time.monotonic())


@algorithms_app.command("compare")
def algorithms_compare(
    ctx: typer.Context,
    carrier: Path = typer.Option(..., "--carrier"),
    payload: Path = typer.Option(..., "--payload"),
    output: Path | None = typer.Option(None, "--output"),
) -> None:
    """Compare the algorithms that apply to a carrier."""
    import time

    kind = detect_format(carrier)
    names = [name for name, info in algorithm_catalogue().items() if kind in info.formats]
    rows = benchmark(carrier, payload.read_bytes(), names, _limits(ctx))
    if output is not None:
        write_table(rows, output)
    _emit(
        ctx,
        Result("algorithms compare", data={"results": rows, "output": str(output) if output else ""}),
        time.monotonic(),
    )


@algorithms_app.command("benchmark")
def algorithms_benchmark(
    ctx: typer.Context,
    carrier: Path = typer.Option(..., "--carrier"),
    payload: Path = typer.Option(..., "--payload"),
) -> None:
    """Benchmark applicable algorithms."""
    algorithms_compare(ctx, carrier, payload)


@payload_app.command("inspect")
def payload_inspect(ctx: typer.Context, package: Path) -> None:
    """Describe a packaged payload."""
    import time

    from lupaxa.dead_drop.payload.package import package_info, package_path

    info = package_info(package_path(package, limits=_limits(ctx)))
    _emit(ctx, Result("payload inspect", data=info.__dict__), time.monotonic())


@payload_app.command("pack")
def payload_pack(ctx: typer.Context, source: Path, output: Path = typer.Option(..., "--output")) -> None:
    """Write a versioned payload package."""
    import time

    from lupaxa.dead_drop.payload.package import package_path

    output.write_bytes(package_path(source, limits=_limits(ctx)))
    _emit(ctx, Result("payload pack", data={"output": str(output)}), time.monotonic())


@payload_app.command("unpack")
def payload_unpack(ctx: typer.Context, package: Path, output: Path = typer.Option(..., "--output")) -> None:
    """Unpack a payload package."""
    import time

    from lupaxa.dead_drop.payload.package import unpack_package

    unpack_package(package.read_bytes(), output, limits=_limits(ctx))
    _emit(ctx, Result("payload unpack", data={"output": str(output)}), time.monotonic())


@payload_app.command("verify")
def payload_verify(ctx: typer.Context, package: Path) -> None:
    """Check a package header."""
    payload_inspect(ctx, package)


@slots_app.command("list")
def slots_list(ctx: typer.Context, carrier: Path) -> None:
    """List named slots. Slot metadata is not inherently concealed."""
    import time

    _emit(
        ctx,
        Result(
            "slots list",
            data={
                "slots": _read_slots(carrier, ctx),
                "warning": "Named slots are a management record, not a concealment guarantee.",
            },
        ),
        time.monotonic(),
    )


@slots_app.command("inspect")
def slots_inspect(ctx: typer.Context, carrier: Path, slot: str = typer.Option(..., "--slot")) -> None:
    """Inspect one slot."""
    import time

    found = next((item for item in _read_slots(carrier, ctx) if item["name"] == slot), None)
    _emit(ctx, Result("slots inspect", data={"slot": found}), time.monotonic())


@slots_app.command("reserve")
def slots_reserve(
    ctx: typer.Context,
    carrier: Path,
    slot: str = typer.Option(..., "--slot"),
    output: Path = typer.Option(..., "--output"),
) -> None:
    """Reserve a named slot in a new carrier copy."""
    import time

    slots = _read_slots(carrier, ctx)
    if any(item["name"] == slot for item in slots):
        raise typer.Exit(
            _fail(ctx, "slots reserve", DeadDropError(f"Slot {slot} already exists.", code="output_collision"))
        )
    slots.append({"name": slot, "bytes": 0, "occupied": False})
    _write_slots(carrier, output, slots, ctx)
    _emit(ctx, Result("slots reserve", data={"slot": slot, "output": str(output)}), time.monotonic())


@slots_app.command("remove")
def slots_remove(
    ctx: typer.Context,
    carrier: Path,
    slot: str = typer.Option(..., "--slot"),
    output: Path = typer.Option(..., "--output"),
) -> None:
    """Remove a named slot from a new carrier copy."""
    import time

    slots = [item for item in _read_slots(carrier, ctx) if item["name"] != slot]
    _write_slots(carrier, output, slots, ctx)
    _emit(ctx, Result("slots remove", data={"slot": slot, "output": str(output)}), time.monotonic())


def _read_slots(carrier: Path, ctx: typer.Context) -> list[dict[str, Any]]:
    return read_slots(carrier, _limits(ctx))


def _write_slots(carrier: Path, output: Path, slots: list[dict[str, Any]], ctx: typer.Context) -> None:
    write_slots(carrier, output, slots, _limits(ctx))


@vault_app.command("create")
def vault_create(
    ctx: typer.Context,
    directory: Path,
    name: str = typer.Option(..., "--name"),
    encrypt: bool = typer.Option(True, "--encrypt/--no-encrypt"),
    redundancy: int = typer.Option(1, "--redundancy"),
    password_file: Path | None = typer.Option(None, "--password-file"),
) -> None:
    """Create an encrypted carrier-backed vault and reopen it to confirm."""
    import time

    started = time.monotonic()
    try:
        if not encrypt:
            raise DeadDropError("Vault creation requires encryption.", code="invalid_arguments")
        vault = create_vault(
            directory,
            _password(ctx, password_file, confirm=True),
            VaultSettings(name=name, redundancy=redundancy, kdf=_kdf(ctx)),
            _limits(ctx),
        )
        _emit(
            ctx,
            Result(
                "vault create",
                data={"vault_id": vault.state["vault_id"], "capacity_bytes": vault.usable_capacity(_limits(ctx))},
            ),
            started,
        )
    except DeadDropError as exc:
        raise typer.Exit(_fail(ctx, "vault create", exc)) from exc


@vault_app.command("open")
def vault_open(
    ctx: typer.Context, directory: Path, password_file: Path | None = typer.Option(None, "--password-file")
) -> None:
    """Open a vault and report its generation."""
    import time

    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    _emit(
        ctx, Result("vault open", data={"generation": vault.generation, "name": vault.state["name"]}), time.monotonic()
    )


@vault_app.command("close")
def vault_close(ctx: typer.Context) -> None:
    """Close is process-local. The in-memory key is discarded when the process exits."""
    import time

    _emit(ctx, Result("vault close", data={"closed": True}), time.monotonic())


@vault_app.command("status")
def vault_status(
    ctx: typer.Context, directory: Path, password_file: Path | None = typer.Option(None, "--password-file")
) -> None:
    """Show vault generation and capacity."""
    import time

    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    _emit(
        ctx,
        Result(
            "vault status", data={"generation": vault.generation, "capacity_bytes": vault.usable_capacity(_limits(ctx))}
        ),
        time.monotonic(),
    )


@vault_app.command("ls")
def vault_ls(
    ctx: typer.Context, directory: Path, password_file: Path | None = typer.Option(None, "--password-file")
) -> None:
    """List the vault root."""
    import time

    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    _emit(ctx, Result("vault ls", data={"entries": listing(vault)}), time.monotonic())


@vault_app.command("tree")
def vault_tree(
    ctx: typer.Context, directory: Path, password_file: Path | None = typer.Option(None, "--password-file")
) -> None:
    """Print the vault tree."""
    import time

    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    _emit(ctx, Result("vault tree", data={"paths": tree_lines(vault)}), time.monotonic())


@vault_app.command("put")
def vault_put(
    ctx: typer.Context,
    directory: Path,
    source: Path,
    vault_path: str,
    password_file: Path | None = typer.Option(None, "--password-file"),
) -> None:
    """Store a file in the vault."""
    import time

    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    vault.put(source, vault_path, _limits(ctx))
    vault.commit(_limits(ctx))
    _emit(ctx, Result("vault put", data={"path": vault_path, "generation": vault.generation}), time.monotonic())


@vault_app.command("get")
def vault_get(
    ctx: typer.Context,
    directory: Path,
    vault_path: str,
    output: Path = typer.Option(..., "--output"),
    password_file: Path | None = typer.Option(None, "--password-file"),
) -> None:
    """Retrieve a vault file."""
    import time

    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    output.write_bytes(vault.get(vault_path, _limits(ctx)))
    _emit(ctx, Result("vault get", data={"output": str(output)}), time.monotonic())


@vault_app.command("cat")
def vault_cat(
    ctx: typer.Context,
    directory: Path,
    vault_path: str,
    password_file: Path | None = typer.Option(None, "--password-file"),
) -> None:
    """Print a vault file to stdout when it is valid UTF-8."""
    import time

    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    sys.stdout.buffer.write(vault.get(vault_path, _limits(ctx)))
    _emit(ctx, Result("vault cat", data={"path": vault_path}), time.monotonic())


@vault_app.command("mkdir")
def vault_mkdir(
    ctx: typer.Context,
    directory: Path,
    vault_path: str,
    password_file: Path | None = typer.Option(None, "--password-file"),
) -> None:
    """Create a vault directory."""
    import time

    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    mkdir(vault, vault_path)
    vault.state["generation"] += 1
    vault.commit(_limits(ctx))
    _emit(ctx, Result("vault mkdir", data={"path": vault_path}), time.monotonic())


@vault_app.command("rmdir")
def vault_rmdir(
    ctx: typer.Context,
    directory: Path,
    vault_path: str,
    password_file: Path | None = typer.Option(None, "--password-file"),
) -> None:
    """Remove an empty vault directory."""
    import time

    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    from lupaxa.dead_drop.vault.store import _require

    node = _require(vault.state["tree"], vault_path, "dir")
    if node["entries"]:
        raise typer.Exit(_fail(ctx, "vault rmdir", DeadDropError("Directory is not empty.", code="filesystem_error")))
    parent = vault.state["tree"]
    for part in Path(vault_path).parts[:-1]:
        parent = parent["entries"][part]
    del parent["entries"][Path(vault_path).name]
    vault.state["generation"] += 1
    vault.commit(_limits(ctx))
    _emit(ctx, Result("vault rmdir", data={"path": vault_path}), time.monotonic())


@vault_app.command("rm")
def vault_rm(
    ctx: typer.Context,
    directory: Path,
    vault_path: str,
    password_file: Path | None = typer.Option(None, "--password-file"),
) -> None:
    """Delete a vault file."""
    import time

    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    remove(vault, vault_path)
    vault.state["generation"] += 1
    vault.commit(_limits(ctx))
    _emit(ctx, Result("vault rm", data={"path": vault_path}), time.monotonic())


@vault_app.command("mv")
def vault_mv(
    ctx: typer.Context,
    directory: Path,
    source: str,
    destination: str,
    password_file: Path | None = typer.Option(None, "--password-file"),
) -> None:
    """Move a vault path."""
    import time

    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    move(vault, source, destination)
    vault.state["generation"] += 1
    vault.commit(_limits(ctx))
    _emit(ctx, Result("vault mv", data={"source": source, "destination": destination}), time.monotonic())


@vault_app.command("cp")
def vault_cp(
    ctx: typer.Context,
    directory: Path,
    source: str,
    destination: str,
    password_file: Path | None = typer.Option(None, "--password-file"),
) -> None:
    """Copy a vault file."""
    import time

    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    copy_path(vault, source, destination)
    vault.state["generation"] += 1
    vault.commit(_limits(ctx))
    _emit(ctx, Result("vault cp", data={"source": source, "destination": destination}), time.monotonic())


@vault_app.command("find")
def vault_find(
    ctx: typer.Context, directory: Path, text: str, password_file: Path | None = typer.Option(None, "--password-file")
) -> None:
    """Find vault paths."""
    import time

    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    _emit(ctx, Result("vault find", data={"matches": find(vault, text)}), time.monotonic())


@vault_app.command("info")
def vault_info(
    ctx: typer.Context,
    directory: Path,
    vault_path: str,
    password_file: Path | None = typer.Option(None, "--password-file"),
) -> None:
    """Show metadata for one vault path."""
    import time

    from lupaxa.dead_drop.vault.store import _require

    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    node = _require(vault.state["tree"], vault_path, "file")
    public = {key: value for key, value in node.items() if key != "blocks"}
    _emit(ctx, Result("vault info", data=public), time.monotonic())


@vault_app.command("capacity")
def vault_capacity(
    ctx: typer.Context, directory: Path, password_file: Path | None = typer.Option(None, "--password-file")
) -> None:
    """Report usable vault capacity."""
    vault_status(ctx, directory, password_file)


@vault_app.command("verify")
def vault_verify(
    ctx: typer.Context,
    directory: Path,
    deep: bool = typer.Option(False, "--deep", is_flag=True),
    password_file: Path | None = typer.Option(None, "--password-file"),
) -> None:
    """Verify vault metadata and, with --deep, every file."""
    import time

    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    _emit(ctx, Result("vault verify", data=verify_vault(vault, _limits(ctx), deep=deep)), time.monotonic())


@vault_app.command("repair")
def vault_repair(
    ctx: typer.Context,
    directory: Path,
    apply: bool = typer.Option(False, "--apply", is_flag=True),
    password_file: Path | None = typer.Option(None, "--password-file"),
) -> None:
    """Show a repair plan before any rewrite."""
    import time

    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    plan = repair_plan(vault)
    if apply and plan["recoverable"]:
        vault.commit(_limits(ctx))
        plan["applied"] = False
        plan["note"] = "No missing shards were found, so no rewrite was required."
    _emit(ctx, Result("vault repair", data=plan), time.monotonic())


@vault_app.command("rebalance")
def vault_rebalance(
    ctx: typer.Context, directory: Path, password_file: Path | None = typer.Option(None, "--password-file")
) -> None:
    """Redistribute shards and adopt new carriers."""
    import time

    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    _emit(ctx, Result("vault rebalance", data=rebalance(vault, _limits(ctx))), time.monotonic())


@vault_app.command("compact")
def vault_compact(
    ctx: typer.Context, directory: Path, password_file: Path | None = typer.Option(None, "--password-file")
) -> None:
    """Drop blocks that no generation or snapshot still references."""
    import time

    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    _emit(ctx, Result("vault compact", data=compact(vault, _limits(ctx))), time.monotonic())


@vault_app.command("snapshot")
def vault_snapshot(
    ctx: typer.Context,
    directory: Path,
    name: str | None = typer.Option(None, "--name"),
    restore: str | None = typer.Option(None, "--restore"),
    delete: str | None = typer.Option(None, "--delete"),
    list_snapshots: bool = typer.Option(False, "--list", is_flag=True),
    password_file: Path | None = typer.Option(None, "--password-file"),
) -> None:
    """Create, list, restore, or delete a snapshot."""
    import time

    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    if list_snapshots:
        data: dict[str, Any] = {"snapshots": vault.state["snapshots"]}
    elif restore:
        restore_snapshot(vault, restore, _limits(ctx))
        data = {"restored": restore}
    elif delete:
        vault.state["snapshots"] = [item for item in vault.state["snapshots"] if item["name"] != delete]
        vault.state["generation"] += 1
        vault.commit(_limits(ctx))
        data = {"deleted": delete}
    elif name:
        data = snapshot(vault, name, _limits(ctx))
    else:
        raise typer.Exit(
            _fail(
                ctx,
                "vault snapshot",
                DeadDropError("Choose --name, --list, --restore, or --delete.", code="invalid_arguments"),
            )
        )
    _emit(ctx, Result("vault snapshot", data=data), time.monotonic())


@vault_app.command("restore")
def vault_restore(
    ctx: typer.Context,
    directory: Path,
    name: str = typer.Option(..., "--name"),
    password_file: Path | None = typer.Option(None, "--password-file"),
) -> None:
    """Restore a snapshot."""
    import time

    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    restore_snapshot(vault, name, _limits(ctx))
    _emit(ctx, Result("vault restore", data={"name": name}), time.monotonic())


@vault_app.command("backup")
def vault_backup(
    ctx: typer.Context,
    directory: Path,
    output: Path = typer.Option(..., "--output"),
    password_file: Path | None = typer.Option(None, "--password-file"),
) -> None:
    """Export an encrypted backup that can be restored without the carriers."""
    import time

    password = _password(ctx, password_file)
    vault = open_vault(directory, password, _kdf(ctx), _limits(ctx))
    backup(vault, output, password, _kdf(ctx), _limits(ctx))
    _emit(ctx, Result("vault backup", data={"output": str(output), "format": "DDBK/1"}), time.monotonic())


@vault_app.command("recover")
def vault_recover(
    ctx: typer.Context,
    directory: Path | None = None,
    backup_path: Path | None = typer.Option(None, "--backup"),
    output: Path | None = typer.Option(None, "--output"),
    password_file: Path | None = typer.Option(None, "--password-file"),
) -> None:
    """Recover a vault from carriers, or restore a backup into a directory."""
    import time

    if backup_path is not None:
        if output is None:
            raise typer.Exit(
                _fail(
                    ctx, "vault recover", DeadDropError("--output is required with --backup.", code="invalid_arguments")
                )
            )
        data = restore_backup(backup_path, output, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    else:
        if directory is None:
            raise typer.Exit(
                _fail(
                    ctx,
                    "vault recover",
                    DeadDropError("Provide a carrier directory or --backup.", code="invalid_arguments"),
                )
            )
        vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
        data = {"generation": vault.generation, "vault_id": vault.state["vault_id"], "files": tree_lines(vault)}
    _emit(ctx, Result("vault recover", data=data), time.monotonic())


@vault_app.command("destroy")
def vault_destroy(
    ctx: typer.Context, directory: Path, password_file: Path | None = typer.Option(None, "--password-file")
) -> None:
    """Replace vault embeddings. This does not promise secure deletion."""
    import time

    if not _state(ctx).force:
        raise typer.Exit(
            _fail(
                ctx,
                "vault destroy",
                DeadDropError("Refusing to destroy a vault without --force.", code="invalid_arguments"),
            )
        )
    vault = open_vault(directory, _password(ctx, password_file), _kdf(ctx), _limits(ctx))
    _emit(
        ctx,
        Result(
            "vault destroy",
            data=destroy(vault, _limits(ctx)),
            warnings=["Secure deletion from SSDs and old copies is not guaranteed."],
        ),
        time.monotonic(),
    )


@challenge_app.command("create")
def challenge_create(
    ctx: typer.Context,
    difficulty: str = typer.Option("easy", "--difficulty"),
    output: Path = typer.Option(..., "--output"),
    seed: str = typer.Option("local", "--seed"),
) -> None:
    """Create a challenge. The solution is written only under .private."""
    import time

    _emit(
        ctx,
        Result("challenge create", data=create_challenge(output, difficulty=difficulty, seed=seed)),
        time.monotonic(),
    )


@challenge_app.command("generate")
def challenge_generate(
    ctx: typer.Context,
    difficulty: str = typer.Option("medium", "--difficulty"),
    output: Path = typer.Option(..., "--output"),
    seed: str = typer.Option("local", "--seed"),
) -> None:
    """Generate a challenge from a seed."""
    challenge_create(ctx, difficulty, output, seed)


@challenge_app.command("inspect")
def challenge_inspect(ctx: typer.Context, directory: Path) -> None:
    """Show public challenge metadata."""
    import time

    _emit(
        ctx,
        Result("challenge inspect", data=json.loads((directory / "challenge.json").read_text(encoding="utf-8"))),
        time.monotonic(),
    )


@challenge_app.command("solve")
def challenge_solve(ctx: typer.Context, directory: Path, answer: Path = typer.Option(..., "--answer")) -> None:
    """Check a proposed solution against the public commitment."""
    import time

    _emit(ctx, Result("challenge solve", data=verify_challenge(directory, answer.read_bytes())), time.monotonic())


@challenge_app.command("verify")
def challenge_verify(ctx: typer.Context, directory: Path, answer: Path = typer.Option(..., "--answer")) -> None:
    """Verify a solution commitment."""
    challenge_solve(ctx, directory, answer)


@audit_app.command("recovery")
def audit_recovery_cmd(ctx: typer.Context, plan_path: Path, mode: str = typer.Option("analytical", "--mode")) -> None:
    """Audit a saved plan. Analytical guarantees are labelled separately from samples."""
    import time

    plan_data = json.loads(plan_path.read_text(encoding="utf-8"))
    _emit(ctx, Result("audit recovery", data=audit_recovery(plan_data, mode=mode)), time.monotonic())


@audit_app.command("integrity")
def audit_integrity(ctx: typer.Context, carrier: Path) -> None:
    """Validate a carrier and report envelope facts."""
    import time

    _emit(ctx, Result("audit integrity", data=analyse_file(carrier, _limits(ctx), deep=True)), time.monotonic())


@audit_app.command("report")
def audit_report(ctx: typer.Context, plan_path: Path, output: Path = typer.Option(..., "--output")) -> None:
    """Write a Markdown recovery report with no secrets in it."""
    import time

    data = audit_recovery(json.loads(plan_path.read_text(encoding="utf-8")), mode="analytical")
    output.write_text("# Recovery Report\n\n" + json.dumps(data, indent=2) + "\n", encoding="utf-8")
    _emit(ctx, Result("audit report", data={"output": str(output)}), time.monotonic())


@recipe_app.command("validate")
def recipe_validate(ctx: typer.Context, path: Path) -> None:
    """Validate a TOML recipe."""
    import time

    recipe = load_recipe(path)
    _emit(
        ctx,
        Result("recipe validate", data={"operation": recipe["recipe"]["operation"], "valid": True}),
        time.monotonic(),
    )


@recipe_app.command("plan")
def recipe_plan(ctx: typer.Context, path: Path) -> None:
    """Dry-run a recipe."""
    import time

    _emit(ctx, Result("recipe plan", data=run_recipe(path, _limits(ctx), password="", dry_run=True)), time.monotonic())


@recipe_app.command("run")
def recipe_run(
    ctx: typer.Context, path: Path, password_file: Path | None = typer.Option(None, "--password-file")
) -> None:
    """Run a recipe."""
    import time

    try:
        if path.suffix == ".json":
            result = execute_plan(
                path,
                _limits(ctx),
                password=_password(ctx, password_file, confirm=True),
                output=path.parent / "executed",
                kdf=_kdf(ctx),
            )
        else:
            result = run_recipe(
                path,
                _limits(ctx),
                password=_password(ctx, password_file, confirm=True),
                dry_run=_state(ctx).dry_run,
                kdf=_kdf(ctx),
            )
        _emit(ctx, Result("recipe run", data=result), time.monotonic())
    except DeadDropError as exc:
        raise typer.Exit(_fail(ctx, "recipe run", exc)) from exc


@app.command()
def interactive() -> None:
    """Open the terminal interface."""
    from lupaxa.dead_drop.tui import DeadDropApp

    DeadDropApp().run()


@app.command("history")
def history_cmd(ctx: typer.Context) -> None:
    """Show local operation history. It is disableable in configuration and stores no secrets."""
    import time

    _emit(ctx, Result("history", data={"records": read_history()}), time.monotonic())


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and translate failures into exit codes."""
    try:
        app(args=argv, standalone_mode=False)
    except DeadDropError as exc:
        typer.echo(str(exc), err=True)
        return exc.exit_code
    except PartialBatchError as exc:
        typer.echo(str(exc), err=True)
        return exc.exit_code
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else 0
    except typer.Exit as exc:
        return int(exc.exit_code or 0)
    return 0
