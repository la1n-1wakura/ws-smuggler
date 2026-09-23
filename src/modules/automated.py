"""Запуск конфигурируемых WebSocket-тестов."""

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.connection import WSConnection
from core.frame_builder import FrameBuilder
from core.frame_parser import WebSocketFrame
from ui.views import console
from rich.table import Table


DEFAULT_PAYLOADS = Path(__file__).resolve().parents[2] / "config" / "default_payloads.json"
VALID_STATUSES = {"response", "closed", "timeout", "protocol_error", "error"}
VALID_SCENARIOS = {"standard", "length_desync", "extra_padding", "nested_frame"}


def _require(condition: bool, message: str) -> None:
	if not condition:
		raise ValueError(f"invalid automated config: {message}")


def validate_config(data: Any) -> list[dict[str, Any]]:
	"""Validate the configuration before any connection is opened."""
	_require(isinstance(data, dict), "root must be an object")
	_require(isinstance(data.get("cases"), list), "cases must be a list")
	targets = data.get("targets", [])
	_require(isinstance(targets, list), "targets must be a list")
	for target in targets:
		_require(isinstance(target, dict), "each target must be an object")
		for field in ("target_id", "proxy_id", "backend_id", "port"):
			_require(field in target, f"target missing {field}")
	groups = data.get("groups", {})
	_require(isinstance(groups, dict), "groups must be an object")
	case_ids = set()
	for case in data["cases"]:
		_require(isinstance(case, dict), "each case must be an object")
		for field in ("experiment_id", "name", "category", "expected_status", "expected_response"):
			_require(field in case, f"case missing {field}")
		experiment_id = case["experiment_id"]
		_require(isinstance(experiment_id, str) and bool(experiment_id), "experiment_id must be non-empty")
		_require(experiment_id not in case_ids, f"duplicate experiment_id: {experiment_id}")
		case_ids.add(experiment_id)
		_require(isinstance(case["category"], str) and bool(case["category"]), f"{experiment_id}: category is required")
		expected = case["expected_status"]
		expected_values = expected if isinstance(expected, list) else [expected]
		_require(isinstance(expected_values, list) and all(value in VALID_STATUSES for value in expected_values), f"{experiment_id}: invalid expected_status")
		scenario = case.get("scenario", "standard")
		_require(scenario in VALID_SCENARIOS, f"{experiment_id}: unknown scenario {scenario}")
		_require(isinstance(case.get("destructive", False), bool), f"{experiment_id}: destructive must be boolean")
		if scenario == "length_desync":
			_require("payload" in case and "declared_length" in case, f"{experiment_id}: payload and declared_length are required")
		if scenario == "nested_frame":
			_require("inner_payload" in case, f"{experiment_id}: inner_payload is required")
		if case.get("payload_encoding") == "hex":
			try:
				bytes.fromhex(str(case.get("payload", "")))
			except ValueError as error:
				raise ValueError(f"invalid automated config: {experiment_id}: payload is not valid hex") from error
	for group, members in groups.items():
		_require(isinstance(members, list) and all(member in case_ids for member in members), f"group {group} contains unknown experiment_id")
	return data["cases"]


def load_cases(config_path: str | Path = DEFAULT_PAYLOADS) -> list[dict[str, Any]]:
	with Path(config_path).open(encoding="utf-8") as config_file:
		data = json.load(config_file)
	cases = validate_config(data)
	targets = data.get("targets", [])
	if targets:
		for case in cases:
			case.setdefault("targets", targets)
	return cases


def load_groups(config_path: str | Path = DEFAULT_PAYLOADS) -> dict[str, list[str]]:
	with Path(config_path).open(encoding="utf-8") as config_file:
		data = json.load(config_file)
	validate_config(data)
	return data.get("groups", {})


def load_case_by_id(
	experiment_id: str,
	config_path: str | Path = DEFAULT_PAYLOADS,
) -> dict[str, Any]:
	"""Load one reproducible experiment by its stable identifier."""
	for case in load_cases(config_path):
		if case.get("experiment_id") == experiment_id:
			return case
	raise ValueError(f"unknown experiment_id: {experiment_id}")


def _target_metadata(case: dict[str, Any], target_id: str | None) -> dict[str, Any]:
	targets = case.get("targets", [])
	if target_id is not None:
		for target in targets:
			if target.get("target_id") == target_id:
				return {"target_id": target_id, "proxy_id": target.get("proxy_id", "unknown"), "backend_id": target.get("backend_id", "unknown")}
		raise ValueError(f"unknown target_id: {target_id}")
	if targets:
		target = targets[0]
		return {"target_id": target.get("target_id", "default"), "proxy_id": target.get("proxy_id", "unknown"), "backend_id": target.get("backend_id", "unknown")}
	return {"target_id": "default", "proxy_id": case.get("proxy_id", "unknown"), "backend_id": case.get("backend_id", "unknown")}


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
	if scenario == "extra_padding":
		case = dict(case)
		case["scenario"] = "length_desync"
		case["declared_length"] = len(_payload(case)) + len(bytes.fromhex(case.get("padding_hex", "")))
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
	experiment_id: str | None = None,
	target_id: str | None = None,
	group: str | None = None,
	category: str | None = None,
	max_tests: int | None = None,
	safe_mode: bool = False,
) -> list[dict[str, Any]]:
	"""Отправляет тест-кейсы и возвращает результаты для консоли/отчёта."""
	results: list[dict[str, Any]] = []
	cases = load_cases(config_path)
	if experiment_id is not None:
		cases = [case for case in cases if case.get("experiment_id") == experiment_id or case.get("name") == experiment_id]
		if not cases:
			raise ValueError(f"unknown experiment_id: {experiment_id}")
	if group is not None:
		members = load_groups(config_path).get(group)
		if members is None:
			raise ValueError(f"unknown scenario group: {group}")
		cases = [case for case in cases if case["experiment_id"] in members]
	if category is not None:
		cases = [case for case in cases if case["category"] == category]
	if safe_mode:
		cases = [case for case in cases if not case.get("destructive", False)]
	if max_tests is not None:
		if max_tests <= 0:
			raise ValueError("max_tests must be positive")
		cases = cases[:max_tests]
	for index, case in enumerate(cases):
		name = str(case.get("name", "unnamed"))
		test_started_at = datetime.now(timezone.utc)
		test_started = time.monotonic()
		response_wait_duration_ms = None
		metadata = {
			"experiment_id": case.get("experiment_id", name),
			**_target_metadata(case, target_id),
			"expected_status": case.get("expected_status", "response"),
			"expected_response": case.get("expected_response", {}),
			"session_id": getattr(connection, "session_id", None),
			"dump_paths": getattr(connection, "traffic_dump_paths", {}),
		}
		frame = b""
		try:
			frame = build_case_frame(case)
			connection.send_frame(frame)
			response_wait_started = time.monotonic()
			response = _receive_response(connection)
			response_wait_duration_ms = round((time.monotonic() - response_wait_started) * 1000, 3)
			received_size = response.total_length if isinstance(response, WebSocketFrame) else len(response)
			status = "closed" if not response else "response"
			details = ""
			if isinstance(response, WebSocketFrame):
				if response.opcode == FrameBuilder.OPCODE_CLOSE:
					close_code = int.from_bytes(response.payload[:2], "big") if len(response.payload) >= 2 else None
					status = "protocol_error" if close_code in {1002, 1003, 1007, 1008, 1009} else "closed"
				details = f"opcode={response.opcode}"
			result = {
				"name": name,
				**metadata,
				"actual_status": status,
				"status": status,
				"sent": len(frame),
				"received": received_size,
				"sent_hex": frame.hex(" "),
				"error": details,
			}
			if isinstance(response, WebSocketFrame):
				result.update({
					"response_opcode": response.opcode,
					"response_kind": "control" if response.is_control else "data",
					"response_fin": response.fin,
					"response_masked": response.masked,
					"response_payload_hex": response.payload.hex(" "),
					"response_payload_text": response.payload.decode("utf-8", errors="replace"),
				})
				if response.opcode == FrameBuilder.OPCODE_CLOSE:
					result["close_code"] = response.close_code
					result["close_reason"] = response.close_reason
			else:
				result.update({"response_payload_hex": response.hex(" "), "response_payload_text": response.decode("utf-8", errors="replace")})
			results.append(result)
		except TimeoutError:
			results.append({"name": name, **metadata, "actual_status": "timeout", "status": "timeout", "sent": len(frame), "received": 0, "sent_hex": frame.hex(" ")})
		except ConnectionError as error:
			results.append({"name": name, **metadata, "actual_status": "closed", "status": "closed", "sent": len(frame), "received": 0, "sent_hex": frame.hex(" "), "error": str(error)})
		except Exception as error:
			actual_status = "protocol_error" if isinstance(error, ValueError) else "error"
			results.append({"name": name, **metadata, "actual_status": actual_status, "status": actual_status, "sent": len(frame), "received": 0, "sent_hex": frame.hex(" "), "error": str(error)})
		results[-1]["matches_expected"] = _matches_expected(
			results[-1]["actual_status"], metadata["expected_status"]
		)
		results[-1].update({
			"started_at": test_started_at.isoformat(),
			"ended_at": datetime.now(timezone.utc).isoformat(),
			"duration_ms": round((time.monotonic() - test_started) * 1000, 3),
			"handshake_duration_ms": getattr(connection, "last_handshake_duration_ms", None),
			"response_wait_duration_ms": response_wait_duration_ms,
		})

		# Аномальный frame может закрыть соединение. Изолируем следующий тест.
		if index < len(cases) - 1 and hasattr(connection, "close") and hasattr(connection, "connect"):
			try:
				connection.close(close_logger=False)
				response = connection.connect()
				if "101 Switching Protocols" not in response:
					raise ConnectionError("failed to reconnect between automated cases")
			except Exception as error:
				results[-1]["reconnect_error"] = str(error)
				break

	_render_results(results, verbose=verbose)
	return results


def _receive_response(connection: WSConnection) -> WebSocketFrame | bytes:
	"""Использовать parser в рабочем соединении и сохранить совместимость fake-сокетов."""
	if hasattr(connection, "receive_frame"):
		return connection.receive_frame()
	return connection.receive()


def _matches_expected(actual_status: str, expected_status: Any) -> bool:
	if isinstance(expected_status, list):
		return actual_status in expected_status
	return actual_status == expected_status


def _render_results(results: list[dict[str, Any]], verbose: bool = False) -> None:
	table = Table(title="Automated results", border_style="cyan")
	table.add_column("Test", style="bold cyan")
	table.add_column("Status")
	table.add_column("Duration", justify="right")
	table.add_column("Sent", justify="right")
	table.add_column("Received", justify="right")
	table.add_column("Details", overflow="fold")
	for result in results:
		details = result.get("error", "")
		table.add_row(result["name"], result["status"], f'{result.get("duration_ms", 0):.3f} ms', str(result["sent"]), str(result["received"]), details)
	console.print(table)
	if verbose:
		for result in results:
			_render_verbose_result(result)


def _render_verbose_result(result: dict[str, Any]) -> None:
	table = Table(title=f"Details: {result['name']}", border_style="yellow")
	table.add_column("Field", style="bold yellow")
	table.add_column("Value", overflow="fold")
	for field in ("status", "response_kind", "sent_hex", "response_opcode", "response_fin", "response_masked", "close_code", "close_reason", "response_payload_hex", "response_payload_text", "error"):
		if field in result and result[field] != "":
			table.add_row(field, str(result[field]))
	console.print(table)
