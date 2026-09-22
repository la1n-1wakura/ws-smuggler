"""CLI-экраны WS-Smuggler."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from prompt_toolkit import PromptSession


console = Console()


def show_banner() -> None:
	console.print(
		Panel.fit(
			"[bold cyan]WS-Smuggler[/bold cyan]\n"
			"[dim]WebSocket frame analysis laboratory[/dim]",
			border_style="cyan",
			padding=(1, 4),
		)
	)


def choose_mode() -> str:
	"""Показывает стартовое меню и возвращает выбранный режим."""
	table = Table(title="Режим работы", border_style="blue")
	table.add_column("№", style="bold cyan", justify="center")
	table.add_column("Режим", style="bold")
	table.add_column("Назначение", style="dim")
	table.add_row("1", "Ручной", "Сборка и отправка одного кадра за раз")
	table.add_row("2", "Автоматический", "Сценарии fuzzing и frame smuggling")
	table.add_row("3", "Запись трафика", "PCAP/hex-лог сырого обмена")
	table.add_row("4", "Выход", "Закрыть программу")
	console.print(table)

	session = PromptSession()
	while True:
		choice = session.prompt("Выберите режим [1-4]: ").strip()
		modes = {"1": "manual", "2": "automated", "3": "traffic", "4": "exit"}
		if choice in modes:
			return modes[choice]
		console.print("[yellow]Введите число от 1 до 4.[/yellow]")


def show_not_implemented(feature: str) -> None:
	console.print(
		Panel(
			f"[yellow]{feature} пока не реализован.[/yellow]\n"
			"Пункт оставлен в интерфейсе как запланированная возможность.",
			title="В разработке",
			border_style="yellow",
		)
	)


def render_frame_result(direction: str, payload: bytes, frame_size: int) -> None:
	"""Показывает отправленный или полученный фрагмент в едином формате."""
	table = Table(title=f"WebSocket {direction}", border_style="cyan")
	table.add_column("Параметр", style="bold cyan")
	table.add_column("Значение")
	table.add_row("Размер", str(frame_size))
	table.add_row("Hex", payload.hex(" ") or "<пусто>")
	table.add_row("Текст", payload.decode("utf-8", errors="replace") or "<пусто>")
	console.print(table)
