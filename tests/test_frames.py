# Юнит-тесты для проверки корректности сборщика кадров

import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from core.connection import WSConnection


class FakeSocket:
    def __init__(self):
        self.closed = False
        self.timeout = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, data):
        pass

    def recv(self, size):
        raise RuntimeError("boom during read")

    def close(self):
        self.closed = True


def test_connect_closes_socket_on_error(monkeypatch):
    fake_socket = FakeSocket()

    def fake_create_connection(*args, **kwargs):
        return fake_socket

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    connection = WSConnection("localhost", 80, timeout=1.0)

    with pytest.raises(RuntimeError, match="boom during read"):
        connection.connect()

    assert fake_socket.closed is True
    assert connection.sock is None


def test_build_frame_masks_payload_and_sets_opcode():
    from core.frame_builder import FrameBuilder

    frame = FrameBuilder.build_frame(b"hello", opcode=0x1, mask=True)

    assert frame[0] == 0x81
    assert frame[1] & 0x80 == 0x80
    assert len(frame) == 2 + 4 + 5
    assert frame[2:6] != b"\x00\x00\x00\x00"


def test_build_frame_supports_custom_length_for_fuzzing():
    from core.frame_builder import FrameBuilder

    frame = FrameBuilder.build_frame(b"abc", opcode=0x2, custom_length=10, mask=False)
    header = frame[0:2]
    assert header[0] == 0x82
    assert header[1] == 10
    assert frame[2:] == b"abc"


def test_manual_input_defaults_and_opcode(monkeypatch):
    from modules import manual

    class FakeSession:
        def __init__(self, values):
            self.values = iter(values)

        def prompt(self, *args, **kwargs):
            return next(self.values)

    session = FakeSession(["", "10"])
    assert manual._read_bool(session, "FIN", True) is True
    assert manual._read_opcode(session) == manual.FrameBuilder.OPCODE_PONG


def test_manual_empty_custom_length_means_actual_length():
    from modules import manual

    class FakeSession:
        def prompt(self, *args, **kwargs):
            return ""

    assert manual._read_int(FakeSession(), "length") is None


def test_automated_mode_loads_cases_and_sends_frames(tmp_path):
    from modules.automated import load_cases, run_automated_mode

    config = tmp_path / "cases.json"
    config.write_text('{"cases": [{"name": "hello", "payload": "hello", "opcode": 1}]}', encoding="utf-8")

    class FakeConnection:
        def __init__(self):
            self.sent = []

        def send_frame(self, frame):
            self.sent.append(frame)

        def receive(self):
            return b"response"

    connection = FakeConnection()
    assert load_cases(config)[0]["name"] == "hello"
    results = run_automated_mode(connection, config)
    assert results[0]["status"] == "response"
    assert connection.sent[0][0] == 0x81
    assert results[0]["sent_hex"].startswith("81 85")


def test_length_desync_supports_under_declaration_with_extra_bytes():
    from modules.automated import build_length_desync_frame

    frame = build_length_desync_frame({
        "payload": "abc",
        "declared_length": 3,
        "padding_hex": "646566",
        "mask": False,
    })

    assert frame[:2] == b"\x81\x03"
    assert frame[2:] == b"abcdef"


def test_nested_frame_contains_unmasked_inner_frame():
    from modules.automated import build_nested_frame

    frame = build_nested_frame({"payload": "outer:", "inner_payload": "secret"})
    masking_key = frame[2:6]
    masked_payload = frame[6:]
    outer_payload = bytes(
        byte ^ masking_key[index % 4]
        for index, byte in enumerate(masked_payload)
    )

    assert outer_payload.startswith(b"outer:")
    assert outer_payload[len(b"outer:"):] == b"\x81\x06secret"


def test_parser_reads_masked_frame_and_unmasks_payload():
    from core.frame_builder import FrameBuilder
    from core.frame_parser import parse_frame

    frame_bytes = FrameBuilder.build_frame(b"hello", mask=True, masking_key=b"abcd")
    frame, end = parse_frame(frame_bytes)

    assert frame.fin is True
    assert frame.opcode == FrameBuilder.OPCODE_TEXT
    assert frame.masked is True
    assert frame.payload == b"hello"
    assert end == len(frame_bytes)


def test_parser_handles_extended_lengths_and_buffered_frames():
    from core.frame_builder import FrameBuilder
    from core.frame_parser import parse_frame

    first = FrameBuilder.build_frame(b"a" * 126, mask=False)
    second = FrameBuilder.build_frame(b"done", opcode=FrameBuilder.OPCODE_TEXT, mask=False)
    frame, offset = parse_frame(first + second)
    next_frame, next_offset = parse_frame(first + second, offset)

    assert frame.payload == b"a" * 126
    assert next_frame.payload == b"done"
    assert next_offset == len(first + second)


def test_connection_receive_frame_reassembles_fragmented_socket_data():
    from core.connection import WSConnection
    from core.frame_builder import FrameBuilder

    frame = FrameBuilder.build_frame(b"fragmented", mask=False)

    class ChunkedSocket:
        def __init__(self, chunks):
            self.chunks = iter(chunks)

        def recv(self, size):
            return next(self.chunks)

    connection = WSConnection("localhost", 80)
    connection.sock = ChunkedSocket([frame[:2], frame[2:]])

    parsed = connection.receive_frame()

    assert parsed.payload == b"fragmented"
    assert parsed.total_length == len(frame)


def test_reporter_exports_json_and_html(tmp_path):
    from ui.reporter import build_report, export_html, export_json

    results = [
        {"name": "ok", "status": "response", "sent": 5, "received": 7},
        {"name": "bad", "status": "timeout", "sent": 8, "received": 0, "error": "read timeout"},
    ]
    report = build_report(results, connection={"host": "localhost", "port": 8080})

    assert report["summary"] == {"total_tests": 2, "responses": 1, "anomalies": 1}
    json_path = export_json(report, output_dir=tmp_path)
    html_path = export_html(report, output_dir=tmp_path)
    assert '"anomalies"' in json_path.read_text(encoding="utf-8")
    html = html_path.read_text(encoding="utf-8")
    assert "viewport" in html
    assert "filter" in html
    assert "read timeout" in html
