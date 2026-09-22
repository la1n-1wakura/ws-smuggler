"""Интерактивная отправка вручную собранных WebSocket-фреймов."""

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import InMemoryHistory

from core.connection import WSConnection
from core.frame_builder import FrameBuilder
from core.frame_parser import WebSocketFrame
from ui.views import console, render_frame_result


OPCODE_NAMES = {
	"1": FrameBuilder.OPCODE_TEXT,
	"2": FrameBuilder.OPCODE_BINARY,
	"8": FrameBuilder.OPCODE_CLOSE,
	"9": FrameBuilder.OPCODE_PING,
	"10": FrameBuilder.OPCODE_PONG,
}


def _prompt_session() -> PromptSession:
	return PromptSession(history=InMemoryHistory())


def _read_opcode(session: PromptSession) -> int:
	completer = WordCompleter(list(OPCODE_NAMES), ignore_case=True)
	while True:
		value = session.prompt("opcode [1=text, 2=binary, 8=close, 9=ping, 10=pong] [1]: ", completer=completer).strip().lower()
		if not value:
			return FrameBuilder.OPCODE_TEXT
		if value in OPCODE_NAMES:
			return OPCODE_NAMES[value]
		console.print("[yellow]Допустимые opcode: 1, 2, 8, 9, 10.[/yellow]")


def _read_int(session: PromptSession, prompt: str) -> int | None:
	while True:
		value = session.prompt(prompt).strip()
		if not value:
			return None
		try:
			return int(value, 0)
		except ValueError:
			console.print("[yellow]Введите целое число или оставьте поле пустым.[/yellow]")


def _read_bool(session: PromptSession, prompt: str, default: bool) -> bool:
	suffix = "Y/n" if default else "y/N"
	while True:
		value = session.prompt(f"{prompt} [{suffix}]: ").strip().lower()
		if not value:
			return default
		if value in {"y", "yes", "д", "да", "1"}:
			return True
		if value in {"n", "no", "н", "нет", "0"}:
			return False
		console.print("[yellow]Введите yes/no или оставьте поле пустым.[/yellow]")


def run_manual_mode(connection: WSConnection) -> None:
	"""Запускает цикл ввода и отправки кадров по активному соединению."""
	console.print("[cyan]Ручной режим. Для выхода введите :quit вместо payload.[/cyan]")
	session = _prompt_session()
	payload_completer = WordCompleter(["hello", "test", "ping", "pong"], ignore_case=True)

	while True:
		payload_text = session.prompt("payload> ", completer=payload_completer)
		if payload_text == ":quit":
			return

		opcode = _read_opcode(session)
		fin = _read_bool(session, "FIN", True)
		mask = _read_bool(session, "Mask", True)
		custom_length = _read_int(session, "custom_length [Enter = фактическая длина]: ")

		frame = FrameBuilder.build_frame(
			payload_text.encode("utf-8"),
			opcode=opcode,
			fin=fin,
			mask=mask,
			custom_length=custom_length,
		)
		connection.send_frame(frame)
		render_frame_result("отправлен", frame, len(frame))

		try:
			response = connection.receive_frame() if hasattr(connection, "receive_frame") else connection.receive()
		except TimeoutError:
			console.print("[yellow]Ответ не получен до истечения таймаута.[/yellow]")
			continue
		if not response:
			console.print("[yellow]Сервер закрыл соединение.[/yellow]")
			return
		if isinstance(response, WebSocketFrame):
			render_frame_result("получен", response.payload, response.total_length)
		else:
			render_frame_result("получен", response, len(response))
