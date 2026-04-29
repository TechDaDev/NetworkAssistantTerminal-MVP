from __future__ import annotations

import json

import httpx
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.prompt import Prompt


DEFAULT_SERVER_URL = "http://127.0.0.1:8765"


console = Console()


def run_chat(server_url: str = DEFAULT_SERVER_URL) -> None:
    _banner()
    console.print("[green]Type `help` for commands. Type `exit` to leave.[/green]")
    with httpx.Client(base_url=server_url, timeout=120.0) as client:
        try:
            health = client.get("/health")
            health.raise_for_status()
        except httpx.HTTPError:
            console.print(
                Panel.fit(
                    f"Local server is not reachable at {server_url}.\nRun `python main.py serve` in another terminal first.",
                    title="Server Offline",
                    border_style="red",
                )
            )
            return

        while True:
            text = Prompt.ask("[bold green]na>[/bold green]").strip()
            if text.lower() in {"exit", "quit", "q"}:
                console.print("[green]Session closed.[/green]")
                return
            if not text:
                continue
            try:
                response = client.post("/command", json={"text": text})
                if response.status_code >= 400:
                    detail = response.json().get("detail", response.text)
                    _print_error(str(detail))
                    continue
                _print_command_response(response.json())
            except httpx.HTTPError as exc:
                _print_error(f"Request failed: {exc}")


def _banner() -> None:
    console.print(
        Panel.fit(
            "NETWORK ASSISTANT :: LOCAL CLI",
            border_style="green",
        )
    )


def _print_command_response(payload: dict) -> None:
    ok = payload.get("ok", False)
    title = payload.get("kind", "response").replace("_", " ").title()
    message = payload.get("message", "")
    data = payload.get("data")
    border = "green" if ok else "yellow"

    if payload.get("kind") == "ask" and isinstance(data, dict) and data.get("answer"):
        console.print(Panel(data["answer"], title="DeepSeek Analysis", border_style=border, expand=False))
        return

    console.print(Panel.fit(message or "--", title=title, border_style=border))
    if data:
        _print_data(data)


def _print_data(data: dict | list) -> None:
    compact = json.dumps(data, indent=2, default=str)
    if len(compact) > 4000:
        compact = compact[:4000] + "\n... truncated ..."
        console.print(compact)
    else:
        console.print(JSON(compact))


def _print_error(message: str) -> None:
    console.print(Panel.fit(message, title="Error", border_style="red"))
