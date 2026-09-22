"""Интерактивная консоль WS-Smuggler."""

from typing import Any

from prompt_toolkit import PromptSession
from rich.table import Table

from core.connection import WSConnection
from modules.manual import run_manual_mode
from ui.views import console, show_not_implemented


class WSSmugglerShell:
    """Командная оболочка для настройки и запуска WebSocket-сессий."""

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        path: str = "/",
        use_ssl: bool = False,
        timeout: float = 10.0,
        insecure: bool = False,
        ca_file: str | None = None,
        initial_mode: str = "manual",
    ) -> None:
        self.options: dict[str, Any] = {
            "host": host,
            "port": port,
            "path": path,
            "ssl": use_ssl,
            "timeout": timeout,
            "insecure": insecure,
            "ca_file": ca_file,
            "mode": initial_mode,
        }
        self.connection: WSConnection | None = None
        self.session = PromptSession()

    def run(self, auto_connect: bool = False) -> None:
        console.print("[dim]Введите help для списка команд.[/dim]")
        if auto_connect:
            if self.connect():
                self.execute_mode()

        while True:
            try:
                command_line = self.session.prompt("ws-smuggler > ").strip()
            except (EOFError, KeyboardInterrupt):
                console.print()
                break

            if not command_line:
                continue
            if not self.handle_command(command_line):
                break

        self.disconnect()

    def handle_command(self, command_line: str) -> bool:
        """Выполнить одну команду; False означает выход из оболочки."""
        parts = command_line.split(maxsplit=2)
        command = parts[0].lower()
        argument = parts[1].lower() if len(parts) > 1 else ""

        if command in {"exit", "quit"}:
            return False
        if command in {"help", "?"}:
            self.show_help()
        elif command in {"show", "options"}:
            self.show_options()
        elif command == "set":
            self.set_option(parts[1:])
        elif command == "connect":
            self.connect()
        elif command == "disconnect":
            self.disconnect()
        elif command in {"run", "start"}:
            self.execute_mode()
        elif command in {"mode", "use"}:
            if argument in {"manual", "automated", "traffic"}:
                self.options["mode"] = argument
                console.print(f"[green]Режим установлен: {argument}[/green]")
            else:
                console.print("[yellow]Использование: use manual|automated|traffic[/yellow]")
        elif command == "banner":
            from ui.views import show_banner

            show_banner()
        else:
            console.print(f"[yellow]Неизвестная команда: {command}. Введите help.[/yellow]")
        return True

    def show_help(self) -> None:
        table = Table(title="Команды WS-Smuggler", border_style="cyan")
        table.add_column("Команда", style="bold cyan")
        table.add_column("Описание")
        table.add_row("show options", "Показать текущие параметры")
        table.add_row("set <опция> <значение>", "Изменить параметр")
        table.add_row("use <режим>", "Выбрать manual, automated или traffic")
        table.add_row("connect", "Установить TCP/TLS и выполнить handshake")
        table.add_row("run", "Запустить выбранный режим")
        table.add_row("disconnect", "Закрыть активное соединение")
        table.add_row("help", "Показать эту справку")
        table.add_row("exit", "Выйти из консоли")
        console.print(table)

    def show_options(self) -> None:
        table = Table(title="Текущие параметры", border_style="blue")
        table.add_column("Опция", style="bold cyan")
        table.add_column("Значение")
        for name, value in self.options.items():
            table.add_row(name, str(value) if value is not None else "<не задано>")
        table.add_row("status", "connected" if self.connection else "disconnected")
        console.print(table)

    def set_option(self, arguments: list[str]) -> None:
        if len(arguments) != 2:
            console.print("[yellow]Использование: set <опция> <значение>[/yellow]")
            return

        name, value = arguments
        if name not in self.options:
            console.print(f"[yellow]Неизвестная опция: {name}[/yellow]")
            return

        previous_value = self.options[name]
        try:
            if name == "mode":
                if value not in {"manual", "automated", "traffic"}:
                    raise ValueError("ожидалось manual, automated или traffic")
                parsed = value
            elif name in {"ssl", "insecure"}:
                if value.lower() not in {"on", "off", "true", "false", "1", "0"}:
                    raise ValueError("ожидалось on/off")
                parsed: Any = value.lower() in {"on", "true", "1"}
            elif name == "port":
                parsed = int(value, 0)
            elif name == "timeout":
                parsed = float(value)
            else:
                parsed = value

            self.options[name] = parsed
            self.validate_tls_options()
            console.print(f"[green]{name} = {parsed}[/green]")
        except ValueError as error:
            self.options[name] = previous_value
            console.print(f"[red]Ошибка параметра: {error}[/red]")

    def validate_tls_options(self) -> None:
        if self.options["insecure"] and self.options["ca_file"]:
            raise ValueError("insecure и ca_file нельзя использовать одновременно")
        if self.options["insecure"] and not self.options["ssl"]:
            raise ValueError("insecure требует ssl=on")
        if self.options["ca_file"] and not self.options["ssl"]:
            raise ValueError("ca_file требует ssl=on")

    def connect(self) -> bool:
        if self.connection is not None:
            console.print("[yellow]Соединение уже установлено.[/yellow]")
            return True
        if not self.options["host"] or not self.options["port"]:
            console.print("[yellow]Сначала задайте host и port через set.[/yellow]")
            return False

        try:
            self.validate_tls_options()
            self.connection = WSConnection(
                host=self.options["host"],
                port=self.options["port"],
                path=self.options["path"],
                use_ssl=self.options["ssl"],
                timeout=self.options["timeout"],
                insecure=self.options["insecure"],
                ca_file=self.options["ca_file"],
            )
            response = self.connection.connect()
            console.print(response)
            if "101 Switching Protocols" not in response:
                console.print("[red]Handshake отклонён сервером.[/red]")
                self.disconnect()
                return False
            console.print("[green]Соединение установлено.[/green]")
            return True
        except Exception as error:
            console.print(f"[red]Ошибка подключения: {error}[/red]")
            self.disconnect()
            return False

    def execute_mode(self) -> None:
        if self.connection is None:
            console.print("[yellow]Сначала установите соединение командой connect.[/yellow]")
            return
        if self.options["mode"] == "manual":
            run_manual_mode(self.connection)
        elif self.options["mode"] == "automated":
            show_not_implemented("Автоматический режим")
        else:
            show_not_implemented("Запись сырого трафика")

    def disconnect(self) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None
            console.print("[dim]Соединение закрыто.[/dim]")
