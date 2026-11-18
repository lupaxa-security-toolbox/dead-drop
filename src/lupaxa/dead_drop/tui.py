"""Textual interface over the same services as the CLI."""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Header, Input, RichLog, Static, TabbedContent, TabPane


class DeadDropApp(App[None]):
    """Keyboard-driven screens for the main Dead Drop workflows."""

    TITLE = "Dead Drop"
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("slash", "focus_search", "Search"),
    ]

    def compose(self) -> ComposeResult:
        """Build the required screens."""
        yield Header()
        with TabbedContent():
            for name in (
                "Dashboard",
                "Carriers",
                "Capacity",
                "Embed",
                "Distribute",
                "Recover",
                "Shares",
                "Analysis",
                "Bit planes",
                "Stress",
                "Algorithms",
                "Vault",
                "Vault health",
                "Challenges",
                "Recipes",
                "History",
            ):
                with TabPane(name, id=name.lower().replace(" ", "-")):
                    yield Static(f"{name}. Use the command line for the full operation, or type a path below.")
                    yield Input(placeholder="Path or command arguments")
                    yield RichLog(highlight=True, markup=True)
        yield Footer()

    def action_focus_search(self) -> None:
        """Focus the first input on the current screen."""
        try:
            self.query_one(Input).focus()
        except Exception:
            return

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Show a preview of the requested path without modifying carriers."""
        from pathlib import Path

        from lupaxa.dead_drop.carriers.api import detect_format

        log = event.input.parent.query_one(RichLog) if event.input.parent else None
        if log is None:
            return
        path = Path(event.value)
        if path.exists():
            try:
                log.write(f"Detected {detect_format(path)}")
            except Exception as exc:
                log.write(str(exc))
        else:
            log.write("Path does not exist yet. No files were changed.")
