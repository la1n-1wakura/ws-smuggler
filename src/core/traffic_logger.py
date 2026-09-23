"""Потоковое логирование сырых байт WebSocket-сессии."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import struct
import json
import uuid

from rich.console import Console
from rich.table import Table


DUMPS_DIR = Path(__file__).resolve().parents[2] / "dumps"
PCAP_MAGIC = 0xA1B2C3D4
PCAP_LINKTYPE_USER0 = 147


def format_hex_dump(data: bytes, width: int = 16) -> str:
	"""Вернуть offset/hex/ASCII dump без изменения исходных байт."""
	if width <= 0:
		raise ValueError("width must be positive")
	lines = []
	for offset in range(0, len(data), width):
		chunk = data[offset:offset + width]
		hex_part = " ".join(f"{byte:02x}" for byte in chunk)
		hex_part = f"{hex_part:<{width * 3 - 1}}"
		ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
		lines.append(f"{offset:08x}  {hex_part}  |{ascii_part}|")
	return "\n".join(lines)


def display_hex_dump(data: bytes, direction: str, console: Console | None = None) -> None:
	"""Вывести один raw chunk через Rich."""
	console = console or Console()
	table = Table(title=f"Traffic {direction}", border_style="cyan")
	table.add_column("Offset", style="bold cyan")
	table.add_column("Hex")
	table.add_column("ASCII")
	for offset in range(0, len(data), 16):
		chunk = data[offset:offset + 16]
		table.add_row(f"{offset:08x}", " ".join(f"{byte:02x}" for byte in chunk), "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk))
	if data:
		console.print(table)


class TrafficLogger:
	"""Пишет каждый send/recv chunk в raw binary, hex и PCAP."""

	def __init__(self, session_name: str | None = None, output_dir: str | Path = DUMPS_DIR, show_hex: bool = True, session_id: str | None = None):
		directory = Path(output_dir)
		directory.mkdir(parents=True, exist_ok=True)
		self.output_dir = directory
		self.session_id = session_id or uuid.uuid4().hex
		stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
		self.stem = self._unique_stem(session_name or f"session-{stamp}")
		self.hex_path = directory / f"{self.stem}.hex"
		self.tx_path = directory / f"{self.stem}.tx.bin"
		self.rx_path = directory / f"{self.stem}.rx.bin"
		self.pcap_path = directory / f"{self.stem}.pcap"
		self.events_path = directory / f"{self.stem}.events.jsonl"
		self.show_hex = show_hex
		self._hex_file = self.hex_path.open("a", encoding="utf-8")
		self._tx_file = self.tx_path.open("ab")
		self._rx_file = self.rx_path.open("ab")
		self._pcap_file = self.pcap_path.open("wb")
		self._events_file = self.events_path.open("a", encoding="utf-8")
		self._write_pcap_header()

	@property
	def paths(self) -> dict[str, str]:
		return {
			"hex": str(self.hex_path),
			"tx_bin": str(self.tx_path),
			"rx_bin": str(self.rx_path),
			"pcap": str(self.pcap_path),
			"events": str(self.events_path),
		}

	def _write_pcap_header(self) -> None:
		self._pcap_file.write(struct.pack("<IHHIIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, PCAP_LINKTYPE_USER0))
		self._pcap_file.flush()

	def _unique_stem(self, stem: str) -> str:
		if not any((self.output_dir / f"{stem}{suffix}").exists() for suffix in (".hex", ".tx.bin", ".rx.bin", ".pcap")):
			return stem
		for index in range(2, 10000):
			candidate = f"{stem}-{index}"
			if not any((self.output_dir / f"{candidate}{suffix}").exists() for suffix in (".hex", ".tx.bin", ".rx.bin", ".pcap")):
				return candidate
		raise FileExistsError("could not allocate a unique traffic log filename")

	def log(self, direction: str, data: bytes) -> None:
		"""Сохранить chunk ровно в том виде, в котором он прошёл через socket."""
		if direction not in {"tx", "rx"}:
			raise ValueError("direction must be tx or rx")
		if not data:
			return
		timestamp = datetime.now(timezone.utc)
		event = {
			"session_id": self.session_id,
			"timestamp": timestamp.isoformat(),
			"direction": direction.upper(),
			"size": len(data),
		}
		self._events_file.write(json.dumps(event, ensure_ascii=False) + "\n")
		self._events_file.flush()
		self._hex_file.write(f"[{timestamp.isoformat()}] {direction.upper()} {len(data)} bytes\n")
		self._hex_file.write(format_hex_dump(data) + "\n")
		self._hex_file.flush()
		binary_file = self._tx_file if direction == "tx" else self._rx_file
		binary_file.write(data)
		binary_file.flush()
		self._pcap_file.write(struct.pack("<IIII", int(timestamp.timestamp()), timestamp.microsecond, len(data), len(data)))
		self._pcap_file.write(data)
		self._pcap_file.flush()
		if self.show_hex:
			display_hex_dump(data, direction)

	def close(self) -> None:
		for file in (self._hex_file, self._tx_file, self._rx_file, self._pcap_file, self._events_file):
			file.close()
