"""Split-terminal health dashboard for vuln-hunter's own scan pipeline.

Run alongside Claude Code (`python dashboard_tui.py`) to watch scan_repo/
scan_diff calls live: success rate, duration percentiles, per-scanner
volumes, and the stopper-bug log with real stack traces.
"""

import psutil
from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Grid
from textual.widgets import Footer, Header, RichLog, Static

import telemetry


class MetricCard(Static):
    def __init__(self, title: str, value: str = "--", subtext: str = "", id: str | None = None):
        super().__init__(id=id)
        self.title_str = title
        self.value_str = value
        self.subtext_str = subtext

    def render(self) -> Text:
        text = Text()
        text.append(f"{self.title_str}\n", style="bold dim")
        text.append(f"{self.value_str}\n", style="bold cyan")
        text.append(self.subtext_str, style="italic dim green")
        return text


class ProcessMonitor(Static):
    def render(self) -> Text:
        pids = telemetry.list_mcp_pids()
        text = Text()
        text.append("MCP Process Watchdog:\n", style="bold yellow")
        if not pids:
            text.append(" [OK] 0 mcp_server.py running\n", style="green")
        elif len(pids) == 1:
            text.append(f" [OK] 1 active (PID {pids[0]})\n", style="green")
        else:
            text.append(f" [WARN] {len(pids)} concurrent instances: {pids}\n", style="bold red")
            text.append(" Press 'k' to keep the newest, kill the rest\n", style="dim red")
        return text


class VulnHunterApp(App):
    CSS = """
    Screen { layout: grid; grid-size: 1; grid-rows: 3 6 5 1fr 3; }
    #metrics-grid { layout: grid; grid-size: 4; grid-columns: 1fr 1fr 1fr 1fr; height: 100%; margin: 0 1; }
    MetricCard { background: $panel; border: solid $primary; padding: 0 1; content-align: center middle; }
    ProcessMonitor { background: $panel; border: solid $secondary; padding: 0 1; margin: 0 1; }
    RichLog { background: $black; border: solid $accent; margin: 0 1; }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh_data", "Refresh"),
        ("k", "kill_extras", "Kill extra MCP"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Grid(
            MetricCard("SUCCESS RATE (24h)", id="m-success"),
            MetricCard("P50 / P90 DURATION", id="m-duration"),
            MetricCard("FP RATE", id="m-fp"),
            MetricCard("STOPPER BUGS (24h)", id="m-bugs"),
            id="metrics-grid",
        )
        yield ProcessMonitor(id="proc-monitor")
        yield RichLog(id="log-stream", highlight=True, markup=True)
        yield Footer()

    def on_mount(self) -> None:
        self.update_telemetry()
        self.set_interval(2.0, self.update_telemetry)

    def action_refresh_data(self) -> None:
        self.update_telemetry()

    def update_telemetry(self) -> None:
        s = telemetry.get_telemetry_summary(hours=24)

        success = self.query_one("#m-success", MetricCard)
        success.value_str = f"{s['success_rate']}%"
        success.subtext_str = f"{s['completed']} ok / {s['hung']} hung / {s['crashed']} crashed"

        duration = self.query_one("#m-duration", MetricCard)
        duration.value_str = f"{s['p50_duration_sec']}s / {s['p90_duration_sec']}s"
        duration.subtext_str = "WARN: p90 near 30min timeout" if s["p90_near_timeout"] else "within budget"

        fp = self.query_one("#m-fp", MetricCard)
        fp.value_str = f"{s['fp_rate']}%"
        zero = s["silent_zero_scanners"]
        fp.subtext_str = f"silent-zero: {', '.join(zero)}" if zero else "no silent-zero scanners"

        bugs = self.query_one("#m-bugs", MetricCard)
        bugs.value_str = str(s["stopper_bugs_count"])
        bugs.subtext_str = f"mcp processes: {s['mcp_process_count']}"

        for widget in (success, duration, fp, bugs):
            widget.refresh()
        self.query_one(ProcessMonitor).refresh()

        log = self.query_one(RichLog)
        log.clear()
        for item in reversed(telemetry.get_recent_events(limit=15)):
            color = "red" if item["event_type"] == "STOPPER_BUG" else ("yellow" if item["event_type"] in ("WARN", "ERROR") else "white")
            log.write(f"[{color}][{item['event_type']}][/{color}] {item['component']}: {item['message']}")
            if item["stack_trace"]:
                log.write(f"[dim]{item['stack_trace'].strip()}[/dim]")

    def action_kill_extras(self) -> None:
        pids = telemetry.list_mcp_pids()
        if len(pids) <= 1:
            self.query_one(RichLog).write("[yellow]Janitor:[/yellow] nothing to kill (0 or 1 process running).")
            return
        # Keep the highest PID (newest process), kill the rest -- never kill
        # blindly like the first draft did, which took down whatever was
        # actively serving a live scan along with any real zombies.
        keep = max(pids)
        killed = 0
        for pid in pids:
            if pid == keep:
                continue
            try:
                psutil.Process(pid).kill()
                killed += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        self.query_one(RichLog).write(f"[bold red]Janitor:[/bold red] kept PID {keep}, killed {killed} extra(s).")


if __name__ == "__main__":
    VulnHunterApp().run()
