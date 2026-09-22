"""Запуск конфигурируемых WebSocket-тестов."""

import json
from pathlib import Path
from typing import Any

from core.connection import WSConnection
from core.frame_builder import FrameBuilder
from core.frame_parser import WebSocketFrame
from ui.views import console
from rich.table import Table


DEFAULT_PAYLOADS = Path(__file__).resolve().parents[2] / "config" / "default_payloads.json"


def load_cases(config_path: str | Path = DEFAULT_PAYLOADS) -> list[dict[str, Any]]:
	with Path(config_path).open(encoding="utf-8") as config_file:
		data = json.load(config_file)
	cases = data.get("cases")
	if not isinstance(cases, list):
		raise ValueError("config must contain a cases list")
	return cases


def _payload(case: dict[str, Any]) -> bytes:
	value = case.get("payload", "")
	if case.get("payload_encoding") == "hex":
		return bytes.fromhex(value)
	return str(value).encode("utf-8")


def build_length_desync_frame(case: dict[str, Any]) -> bytes:
	"""Build a frame whose declared length differs from bytes sent in payload."""
	payload = _payload(case)
	padding = bytes.fromhex(case.get("padding_hex", ""))
	declared_length = int(case["declared_length"])
	return FrameBuilder.build_frame(
		payload + padding,
		opcode=int(case.get("opcode", FrameBuilder.OPCODE_TEXT)),
		fin=bool(case.get("fin", True)),
		mask=bool(case.get("mask", True)),
		custom_length=declared_length,
	)


def build_nested_frame(case: dict[str, Any]) -> bytes:
	"""Embed an unmasked valid frame inside a masked outer text frame."""
	inner_payload = str(case.get("inner_payload", "hidden")).encode("utf-8")
	inner_frame = FrameBuilder.build_frame(
		inner_payload,
		opcode=int(case.get("inner_opcode", FrameBuilder.OPCODE_TEXT)),
		mask=False,
	)
	outer_payload = _payload(case) + inner_frame
	return FrameBuilder.build_frame(
		outer_payload,
		opcode=FrameBuilder.OPCODE_TEXT,
		fin=bool(case.get("fin", True)),
		mask=True,
	)


def build_case_frame(case: dict[str, Any]) -> bytes:
	"""Dispatch a configured case to its frame construction strategy."""
	scenario = case.get("scenario", "standard")
	if scenario == "length_desync":
		return build_length_desync_frame(case)
	if scenario == "nested_frame":
		return build_nested_frame(case)
	if scenario != "standard":
		raise ValueError(f"unknown automated scenario: {scenario}")
	return FrameBuilder.build_frame(
		_payload(case),
		opcode=int(case.get("opcode", FrameBuilder.OPCODE_TEXT)),
		fin=bool(case.get("fin", True)),
		mask=bool(case.get("mask", True)),
		custom_length=case.get("custom_length"),
	)


def run_automated_mode(
	connection: WSConnection,
	config_path: str | Path = DEFAULT_PAYLOADS,
	verbose: bool = False,
) -> list[dict[str, Any]]:
	"""Отправляет тест-кейсы и возвращает результаты для консоли/отчёта."""
	results: list[dict[str, Any]] = []
	cases = load_cases(config_path)
	for index, case in enumerate(cases):
		name = str(case.get("name", "unnamed"))
		frame = b""
		try:
			frame = build_case_frame(case)
			connection.send_frame(frame)
			response = _receive_response(connection)
			received_size = len(response.payload) if isinstance(response, WebSocketFrame) else len(response)
			status = "closed" if not response else "response"
			details = ""
			if isinstance(response, WebSocketFrame):
				status = "closed" if response.opcode == FrameBuilder.OPCODE_CLOSE else status
				details = f"opcode={response.opcode}"
			result = {
				"name": name,
				"status": status,
				"sent": len(frame),
				"received": received_size,
				"sent_hex": frame.hex(" "),
				"error": details,
			}
			if isinstance(response, WebSocketFrame):
				result.update({
					"response_opcode": response.opcode,
					"response_fin": response.fin,
					"response_masked": response.masked,
					"response_payload_hex": response.payload.hex(" "),
					"response_payload_text": response.payload.decode("utf-8", errors="replace"),
				})
			else:
				result.update({"response_payload_hex": response.hex(" "), "response_payload_text": response.decode("utf-8", errors="replace")})
			results.append(result)
		except TimeoutError:
			results.append({"name": name, "status": "timeout", "sent": len(frame), "received": 0, "sent_hex": frame.hex(" ")})
		except Exception as error:
			results.append({"name": name, "status": "error", "sent": len(frame), "received": 0, "sent_hex": frame.hex(" "), "error": str(error)})

		# Аномальный frame может закрыть соединение. Изолируем следующий тест.
		if index < len(cases) - 1 and hasattr(connection, "close") and hasattr(connection, "connect"):
			connection.close()
			response = connection.connect()
			if "101 Switching Protocols" not in response:
				raise ConnectionError("failed to reconnect between automated cases")

	_render_results(results, verbose=verbose)
	return results


def _receive_response(connection: WSConnection) -> WebSocketFrame | bytes:
	"""Использовать parser в рабочем соединении и сохранить совместимость fake-сокетов."""
	if hasattr(connection, "receive_frame"):
		return connection.receive_frame()
	return connection.receive()


def _render_results(results: list[dict[str, Any]], verbose: bool = False) -> None:
	table = Table(title="Automated results", border_style="cyan")
	table.add_column("Test", style="bold cyan")
	table.add_column("Status")
	table.add_column("Sent", justify="right")
	table.add_column("Received", justify="right")
	table.add_column("Details", overflow="fold")
	for result in results:
		details = result.get("error", "")
		table.add_row(result["name"], result["status"], str(result["sent"]), str(result["received"]), details)
	console.print(table)
	if verbose:
		for result in results:
			_render_verbose_result(result)


def _render_verbose_result(result: dict[str, Any]) -> None:
	table = Table(title=f"Details: {result['name']}", border_style="yellow")
	table.add_column("Field", style="bold yellow")
	table.add_column("Value", overflow="fold")
	for field in ("status", "sent_hex", "response_opcode", "response_fin", "response_masked", "response_payload_hex", "response_payload_text", "error"):
		if field in result and result[field] != "":
			table.add_row(field, str(result[field]))
	console.print(table)
