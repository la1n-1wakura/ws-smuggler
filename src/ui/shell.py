"""Интерактивная консоль WS-Smuggler."""

from typing import Any
import ipaddress
import math
import re
from pathlib import Path

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter
from rich.table import Table

from core.connection import WSConnection
from core.traffic_logger import TrafficLogger
from modules.automated import load_cases, run_automated_mode
from modules.manual import run_manual_mode
from ui.reporter import compare_reports, export_html, export_json, build_report, load_report, report_stem
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
        log_traffic: bool = False,
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
            "target_id": None,
            "payloads_file": "config/default_payloads.json",
            "max_tests": None,
            "safe_mode": False,
            "logging": log_traffic,
            "reports_dir": "reports",
            "dumps_dir": "dumps",
        }
        self.connection: WSConnection | None = None
        self.connection_dirty = False
        self.last_results: list[dict[str, Any]] = []
        self.session = PromptSession(completer=self._build_completer())

    def _build_completer(self) -> NestedCompleter:
        """Автодополнение команд и их основных аргументов через Tab."""
        return NestedCompleter.from_nested_dict({
            "help": None,
            "?": None,
            "banner": None,
            "connect": None,
            "disconnect": None,
            "run": {"verbose": None},
            "start": {"verbose": None},
            "exit": None,
            "quit": None,
            "show": {"options": None, "logging": None, "last": None, "reports": None},
            "compare": None,
            "report": {"json": None, "html": None, "all": None},
            "use": {"manual": None, "automated": None, "traffic": None},
            "mode": {"manual": None, "automated": None, "traffic": None},
            "set": {
                "host": None,
                "port": None,
                "path": None,
                "ssl": {"on": None, "off": None},
                "timeout": None,
                "insecure": {"on": None, "off": None},
                "ca_file": None,
                "mode": {"manual": None, "automated": None, "traffic": None},
                "target_id": None,
                "payloads_file": None,
                "max_tests": None,
                "safe_mode": {"on": None, "off": None},
                "logging": {"on": None, "off": None},
                "reports_dir": None,
                "dumps_dir": None,
            },
        })

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
            if argument == "last":
                self.show_last_results()
            elif argument in {"logging", "logs", "dump", "dumps"}:
                self.show_logging_paths()
            elif argument == "reports":
                self.show_reports()
            else:
                self.show_options()
        elif command == "set":
            self.set_option(parts[1:])
        elif command == "connect":
            self.connect()
        elif command == "disconnect":
            self.disconnect()
        elif command == "report":
            self.export_results(argument or "all")
        elif command == "compare":
            self.compare_report_files(parts[1:])
        elif command in {"run", "start"}:
            run_value = parts[2] if len(parts) > 2 else ""
            self.execute_mode(
                verbose=argument == "verbose",
                experiment_id=None if argument in {"", "verbose", "group", "category"} else argument,
                group=run_value if argument == "group" else None,
                category=run_value if argument == "category" else None,
            )
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
        table.add_row("show logging", "Показать session ID и пути dump-файлов")
        table.add_row("show reports", "Показать архив JSON/HTML-отчётов")
        table.add_row("compare <report-a> <report-b>", "Сравнить два JSON-отчёта")
        table.add_row("set <опция> <значение>", "Изменить параметр")
        table.add_row("use <режим>", "Выбрать manual, automated или traffic")
        table.add_row("connect", "Установить TCP/TLS и выполнить handshake")
        table.add_row("run", "Запустить выбранный режим")
        table.add_row("run verbose", "Запустить режим с подробным выводом кадров")
        table.add_row("show last", "Показать подробности последнего запуска")
        table.add_row("report json|html|all", "Сохранить результаты в reports/")
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

    def show_logging_paths(self) -> None:
        """Показать текущую session ID и созданные dump-файлы."""
        if self.connection is None or not self.connection.traffic_dump_paths:
            console.print("[yellow]Активная сессия логирования отсутствует.[/yellow]")
            return
        table = Table(title="Traffic logging", border_style="cyan")
        table.add_column("Field", style="bold cyan")
        table.add_column("Value", overflow="fold")
        table.add_row("session_id", str(self.connection.session_id))
        for name, path in self.connection.traffic_dump_paths.items():
            table.add_row(name, path)
        console.print(table)

    def show_reports(self) -> None:
        report_dir = Path(self.options["reports_dir"]).expanduser()
        paths = sorted(report_dir.glob("*.json")) if report_dir.is_dir() else []
        if not paths:
            console.print("[yellow]JSON-отчёты не найдены.[/yellow]")
            return
        table = Table(title="Report archive", border_style="cyan")
        table.add_column("Run ID", style="bold cyan")
        table.add_column("Generated")
        table.add_column("Path", overflow="fold")
        for path in paths:
            try:
                report = load_report(path)
                table.add_row(str(report.get("run_id", "unknown")), str(report.get("generated_at", "")), str(path))
            except (OSError, ValueError) as error:
                table.add_row("invalid", "", f"{path}: {error}")
        console.print(table)

    def compare_report_files(self, arguments: list[str]) -> None:
        if len(arguments) != 2:
            console.print("[yellow]Использование: compare <report-a.json> <report-b.json>[/yellow]")
            return
        try:
            comparison = compare_reports(load_report(arguments[0]), load_report(arguments[1]))
        except (OSError, ValueError, TypeError) as error:
            console.print(f"[red]Не удалось сравнить отчёты: {error}[/red]")
            return
        table = Table(title="Report comparison", border_style="cyan")
        table.add_column("Change", style="bold cyan")
        table.add_column("Count", justify="right")
        table.add_row("new anomalies", str(len(comparison["new_anomalies"])))
        table.add_row("removed anomalies", str(len(comparison["removed_anomalies"])))
        table.add_row("changed anomalies", str(len(comparison["changed_anomalies"])))
        table.add_row("changed metrics", str(len(comparison["metric_changes"])))
        console.print(table)
        for category in ("new_anomalies", "removed_anomalies"):
            for anomaly in comparison[category]:
                console.print(f"[yellow]{category}: {anomaly.get('test', 'unknown')} -> {anomaly.get('status', 'unknown')}[/yellow]")
        for anomaly in comparison["changed_anomalies"]:
            console.print(
                f"[yellow]changed: {anomaly['key']} "
                f"{anomaly['before'].get('status')} -> {anomaly['after'].get('status')}[/yellow]"
            )
        for key, values in comparison["metric_changes"].items():
            console.print(f"[dim]{key}: {values['before']} -> {values['after']}[/dim]")

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
            elif name == "target_id":
                if not value:
                    raise ValueError("target_id не должен быть пустым")
                parsed = value
            elif name == "payloads_file":
                parsed = str(Path(value).expanduser())
                if not Path(parsed).is_file():
                    raise ValueError("config file does not exist")
            elif name == "max_tests":
                parsed = int(value, 0)
                if parsed <= 0:
                    raise ValueError("max_tests must be positive")
            elif name == "safe_mode":
                if value.lower() not in {"on", "off", "true", "false", "1", "0"}:
                    raise ValueError("ожидалось on/off")
                parsed = value.lower() in {"on", "true", "1"}
            elif name in {"ssl", "insecure", "logging"}:
                if value.lower() not in {"on", "off", "true", "false", "1", "0"}:
                    raise ValueError("ожидалось on/off")
                parsed: Any = value.lower() in {"on", "true", "1"}
            elif name == "port":
                parsed = int(value, 0)
                if not 1 <= parsed <= 65535:
                    raise ValueError("порт должен быть в диапазоне 1-65535")
            elif name == "timeout":
                parsed = float(value)
                if not math.isfinite(parsed) or parsed <= 0:
                    raise ValueError("timeout должен быть конечным числом больше 0")
            elif name == "host":
                parsed = value
                self._validate_host(parsed)
            elif name == "path":
                parsed = value
                if not parsed.startswith("/"):
                    raise ValueError("path должен начинаться с /")
                if any(character in parsed for character in "\r\n"):
                    raise ValueError("path не должен содержать переводы строк")
            elif name == "ca_file":
                parsed = value
                ca_path = Path(parsed).expanduser()
                if not ca_path.is_file():
                    raise ValueError("указанный CA-файл не существует")
            elif name in {"reports_dir", "dumps_dir"}:
                parsed = str(Path(value).expanduser())
                if any(character in parsed for character in "\r\n"):
                    raise ValueError("каталог указан некорректно")
            else:
                parsed = value

            self.options[name] = parsed
            self.validate_tls_options()
            if name in {"host", "port", "path", "ssl", "insecure", "ca_file", "timeout", "logging", "dumps_dir"}:
                self.connection_dirty = True
            console.print(f"[green]{name} = {parsed}[/green]")
        except ValueError as error:
            self.options[name] = previous_value
            console.print(f"[red]Ошибка параметра: {error}[/red]")

    @staticmethod
    def _validate_host(host: str) -> None:
        if not host or any(character.isspace() or ord(character) < 32 for character in host):
            raise ValueError("host не должен быть пустым или содержать пробелы")
        try:
            ipaddress.ip_address(host)
            return
        except ValueError:
            pass
        hostname_pattern = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
        if len(host) > 253 or not re.fullmatch(hostname_pattern, host):
            raise ValueError("host должен быть доменным именем, localhost или IP-адресом")

    def validate_tls_options(self) -> None:
        if self.options["insecure"] and self.options["ca_file"]:
            raise ValueError("insecure и ca_file нельзя использовать одновременно")
        if self.options["insecure"] and not self.options["ssl"]:
            raise ValueError("insecure требует ssl=on")
        if self.options["ca_file"] and not self.options["ssl"]:
            raise ValueError("ca_file требует ssl=on")

    def connect(self) -> bool:
        if self.connection is not None:
            if not self.connection_dirty:
                console.print("[yellow]Соединение уже установлено.[/yellow]")
                return True
            console.print("[cyan]Параметры изменились, переподключаюсь автоматически.[/cyan]")
            self.disconnect(silent=True)
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
                traffic_logger=TrafficLogger(output_dir=self.options["dumps_dir"], show_hex=True) if self.options["logging"] else None,
            )
            response = self.connection.connect()
            console.print(response)
            if "101 Switching Protocols" not in response:
                console.print("[red]Handshake отклонён сервером.[/red]")
                self.disconnect()
                return False
            console.print("[green]Соединение установлено.[/green]")
            self.connection_dirty = False
            return True
        except Exception as error:
            console.print(f"[red]Ошибка подключения: {error}[/red]")
            self.disconnect()
            return False

    def execute_mode(self, verbose: bool = False, experiment_id: str | None = None, group: str | None = None, category: str | None = None) -> None:
        if self.options["mode"] == "automated":
            try:
                load_cases(self.options["payloads_file"])
            except (OSError, ValueError, TypeError) as error:
                console.print(f"[red]Конфигурация отклонена до подключения: {error}[/red]")
                return
        if self.connection is None:
            if not self.connect():
                return
        elif self.connection_dirty and not self.connect():
            return
        if self.options["mode"] == "manual":
            run_manual_mode(self.connection)
            if self.connection is not None and self.connection.sock is None:
                self.connection = None
        elif self.options["mode"] == "automated":
            self.last_results = run_automated_mode(
                self.connection,
                config_path=self.options["payloads_file"],
                verbose=verbose,
                experiment_id=experiment_id,
                target_id=self.options["target_id"],
                group=group,
                category=category,
                max_tests=self.options["max_tests"],
                safe_mode=self.options["safe_mode"],
            )
        else:
            show_not_implemented("Запись сырого трафика")

    def show_last_results(self) -> None:
        if not self.last_results:
            console.print("[yellow]Результатов ещё нет.[/yellow]")
            return
        from modules.automated import _render_verbose_result

        for result in self.last_results:
            _render_verbose_result(result)

    def export_results(self, report_format: str) -> None:
        if not self.last_results:
            console.print("[yellow]Сначала запустите автоматический режим.[/yellow]")
            return
        if report_format not in {"json", "html", "all"}:
            console.print("[yellow]Использование: report json|html|all[/yellow]")
            return

        report = build_report(self.last_results, connection={
            "host": self.options["host"],
            "port": self.options["port"],
            "path": self.options["path"],
            "ssl": self.options["ssl"],
			"session_id": self.connection.session_id if self.connection else None,
			"dump_paths": self.connection.traffic_dump_paths if self.connection else {},
        }, metadata={
            "tool": "WS-Smuggler",
            "mode": self.options["mode"],
            "configuration": {
                "host": self.options["host"],
                "port": self.options["port"],
                "mode": self.options["mode"],
                "target_id": self.options["target_id"],
            },
        })
        paths = []
        json_path = None
        stem = report_stem(report)
        if report_format in {"json", "all"}:
            json_path = export_json(report, stem=stem, output_dir=self.options["reports_dir"])
            paths.append(json_path)
        if report_format in {"html", "all"}:
            if json_path is None:
                json_path = Path(self.options["reports_dir"]) / f"{stem}.json"
            paths.append(export_html(report, stem=json_path.stem, output_dir=self.options["reports_dir"], json_path=json_path))
        for path in paths:
            console.print(f"[green]Отчёт сохранён: {path}[/green]")

    def disconnect(self, silent: bool = False) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None
            if not silent:
                console.print("[dim]Соединение закрыто.[/dim]")
