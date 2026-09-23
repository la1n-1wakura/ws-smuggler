# Юнит-тесты для проверки корректности сборщика кадров

import base64
import json
import socket
import struct
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


class HandshakeSocket:
    def __init__(self, response):
        self.response = response
        self.closed = False

    def settimeout(self, timeout):
        pass

    def sendall(self, data):
        pass

    def recv(self, size):
        response, self.response = self.response, b""
        return response

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


def test_connect_preserves_frame_bytes_received_with_handshake(monkeypatch):
    from core.frame_builder import FrameBuilder

    websocket_key = "dGhlIHNhbXBsZSBub25jZQ=="
    accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    handshake = (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: " + accept.encode("ascii") + b"\r\n\r\n"
    )
    frame = FrameBuilder.build_frame(b"hello", mask=False)
    fake_socket = HandshakeSocket(handshake + frame)
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: fake_socket)
    monkeypatch.setattr("secrets.token_bytes", lambda size: base64.b64decode(websocket_key))

    connection = WSConnection("localhost", 80, timeout=1.0)
    connection.connect()

    assert connection.receive_frame().payload == b"hello"


def test_connect_closes_socket_when_upgrade_is_rejected(monkeypatch):
    fake_socket = HandshakeSocket(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: fake_socket)

    connection = WSConnection("localhost", 80, timeout=1.0)
    response = connection.connect()

    assert "400 Bad Request" in response
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
    config.write_text('{"cases": [{"experiment_id": "hello", "name": "hello", "category": "baseline", "destructive": false, "payload": "hello", "opcode": 1, "expected_status": "response", "expected_response": {}}]}', encoding="utf-8")

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
    assert results[0]["started_at"] < results[0]["ended_at"]
    assert results[0]["duration_ms"] >= 0
    assert results[0]["response_wait_duration_ms"] >= 0


def test_automated_config_supports_groups_categories_limits_and_safe_mode(tmp_path):
    from modules.automated import load_cases, run_automated_mode

    config = tmp_path / "cases.json"
    config.write_text(
        '{"groups": {"smoke": ["safe"]}, "cases": ['
        '{"experiment_id":"safe","name":"safe","category":"baseline","destructive":false,"payload":"ok","expected_status":"response","expected_response":{}},'
        '{"experiment_id":"danger","name":"danger","category":"desync","destructive":true,"scenario":"length_desync","payload":"x","declared_length":2,"expected_status":"closed","expected_response":{}}'
        ']}',
        encoding="utf-8",
    )

    assert load_cases(config)[0]["category"] == "baseline"

    class FakeConnection:
        def send_frame(self, frame):
            pass

        def receive(self):
            return b"ok"

    assert len(run_automated_mode(FakeConnection(), config, group="smoke")) == 1
    assert len(run_automated_mode(FakeConnection(), config, safe_mode=True)) == 1
    assert len(run_automated_mode(FakeConnection(), config, max_tests=1)) == 1


def test_invalid_automated_config_is_rejected():
    from modules.automated import validate_config

    with pytest.raises(ValueError, match="category"):
        validate_config({"cases": [{"experiment_id": "broken", "name": "broken"}]})


def test_invalid_json_schema_is_rejected_before_semantic_checks():
    from modules.automated import validate_config

    with pytest.raises(ValueError, match="schema violation"):
        validate_config({"cases": "not-a-list"})


def test_unknown_category_is_rejected_when_categories_declared():
    from modules.automated import validate_config

    with pytest.raises(ValueError, match="unknown category"):
        validate_config({
            "categories": ["baseline"],
            "cases": [{
                "experiment_id": "broken",
                "name": "broken",
                "category": "not-declared",
                "expected_status": "response",
                "expected_response": {},
            }],
        })


def test_matrix_cases_have_ids_targets_and_can_be_replayed():
    from modules.automated import load_case_by_id, load_cases, run_automated_mode

    cases = load_cases()
    ids = {case["experiment_id"] for case in cases}
    assert {"text_echo", "binary_echo", "ping_pong", "over_declared_length", "under_declared_length", "extra_padding", "nested_frame_injection", "invalid_opcode", "invalid_rsv", "fragmented_frame"} <= ids
    assert {target["target_id"] for target in cases[0]["targets"]} == {"nginx-python", "nginx-nodejs", "haproxy-spring"}
    assert load_case_by_id("invalid_rsv")["rsv1"] is True

    class FakeConnection:
        def send_frame(self, frame):
            self.sent = frame

        def receive(self):
            return b"response"

    result = run_automated_mode(FakeConnection(), experiment_id="text_echo", target_id="haproxy-spring")
    assert result[0]["experiment_id"] == "text_echo"
    assert result[0]["proxy_id"] == "haproxy"
    assert result[0]["backend_id"] == "spring"
    assert result[0]["matches_expected"] is True


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
    report = build_report(results, connection={"host": "localhost", "port": 8080, "dump_paths": {"pcap": "session.pcap"}})

    assert report["summary"]["total_tests"] == 2
    assert report["summary"]["status_counts"] == {"response": 1, "timeout": 1}
    assert report["summary"]["sent_bytes"] == 13
    assert report["summary"]["received_bytes"] == 7
    assert report["summary"]["timeouts"] == 1
    assert report["summary"]["successful_responses"] == 1
    assert report["summary"]["anomaly_percentage"] == 50.0
    assert report["connection"]["dump_paths"]["pcap"] == "session.pcap"
    json_path = export_json(report, output_dir=tmp_path)
    html_path = export_html(report, stem=json_path.stem, output_dir=tmp_path, json_path=json_path)
    assert '"anomalies"' in json_path.read_text(encoding="utf-8")
    html = html_path.read_text(encoding="utf-8")
    assert "viewport" in html
    assert "filter" in html
    assert "read timeout" in html
    assert f'href="{json_path.name}"' in html


def test_report_archive_has_unique_run_ids_and_compare_detects_changes(tmp_path):
    from ui.reporter import build_report, compare_reports, export_json

    first = build_report(
        [{"name": "case", "experiment_id": "case", "target_id": "nginx-python", "status": "timeout", "sent": 10, "received": 0}],
        metadata={"configuration": {"host": "localhost", "port": 8080, "mode": "automated"}},
    )
    second = build_report(
        [{"name": "case", "experiment_id": "case", "target_id": "nginx-python", "status": "closed", "sent": 10, "received": 5}],
        metadata={"configuration": {"host": "localhost", "port": 8080, "mode": "automated"}},
    )
    first_path = export_json(first, output_dir=tmp_path)
    second_path = export_json(second, output_dir=tmp_path)
    assert first["run_id"] != second["run_id"]
    assert first_path != second_path
    assert "localhost-8080-automated" in first_path.name

    comparison = compare_reports(first, second)
    assert len(comparison["changed_anomalies"]) == 1
    assert comparison["metric_changes"]["timeouts"] == {"before": 1, "after": 0}


def test_shell_validates_connection_options(tmp_path):
    from ui.shell import WSSmugglerShell

    shell = WSSmugglerShell()
    shell.set_option(["port", "70000"])
    assert shell.options["port"] is None
    shell.set_option(["host", "not a host"])
    assert shell.options["host"] is None
    shell.set_option(["path", "ws"])
    assert shell.options["path"] == "/"
    shell.set_option(["timeout", "0"])
    assert shell.options["timeout"] == 10.0
    shell.set_option(["ca_file", str(tmp_path / "missing.crt")])
    assert shell.options["ca_file"] is None

    ca_file = tmp_path / "ca.crt"
    ca_file.write_text("certificate", encoding="utf-8")
    shell.set_option(["ssl", "on"])
    shell.set_option(["ca_file", str(ca_file)])
    assert shell.options["ca_file"] == str(ca_file)


def test_traffic_logger_preserves_raw_bytes_and_writes_pcap(tmp_path):
    from core.traffic_logger import TrafficLogger, format_hex_dump

    hex_dump = format_hex_dump(b"ABC")
    assert hex_dump.startswith("00000000  41 42 43")
    assert hex_dump.endswith("|ABC|")
    logger = TrafficLogger(session_name="test-session", output_dir=tmp_path, show_hex=False)
    assert logger.session_id
    logger.log("tx", bytes([0, 65, 66, 67]))
    logger.log("rx", b"reply")
    logger.close()

    assert (tmp_path / "test-session.tx.bin").read_bytes() == bytes([0, 65, 66, 67])
    assert (tmp_path / "test-session.rx.bin").read_bytes() == b"reply"
    pcap = (tmp_path / "test-session.pcap").read_bytes()
    assert len(pcap) > 24
    assert pcap[:4] == bytes([0xD4, 0xC3, 0xB2, 0xA1])
    records = []
    offset = 24
    while offset < len(pcap):
        header = struct.unpack_from("<IIII", pcap, offset)
        offset += 16
        seconds, microseconds, included, original = header
        records.append((seconds, microseconds, included, original, pcap[offset:offset + included]))
        offset += included
    assert [record[2:] for record in records] == [(4, 4, b"\x00ABC"), (5, 5, b"reply")]
    events = [json.loads(line) for line in (tmp_path / "test-session.events.jsonl").read_text().splitlines()]
    assert [event["direction"] for event in events] == ["TX", "RX"]
    assert all(event["session_id"] == logger.session_id for event in events)
    assert all(event["timestamp"] for event in events)


def test_reports_and_logs_do_not_overwrite_existing_files(tmp_path):
    from core.traffic_logger import TrafficLogger
    from ui.reporter import build_report, export_json

    report = build_report([])
    first = export_json(report, output_dir=tmp_path)
    second = export_json(report, output_dir=tmp_path)
    assert first != second
    assert first.exists() and second.exists()

    logger = TrafficLogger(session_name="session", output_dir=tmp_path, show_hex=False)
    logger.close()
    second_logger = TrafficLogger(session_name="session", output_dir=tmp_path, show_hex=False)
    second_logger.close()
    assert second_logger.stem == "session-2"


def test_control_frame_rejects_fragmentation_and_oversized_length():
    from core.frame_builder import FrameBuilder

    with pytest.raises(ValueError, match="control frames"):
        FrameBuilder.build_frame(b"ping", opcode=FrameBuilder.OPCODE_PING, fin=False)
    with pytest.raises(ValueError, match="control frames"):
        FrameBuilder.build_frame(b"x" * 126, opcode=FrameBuilder.OPCODE_PING)


@pytest.mark.parametrize(
    ("raw_frame", "message"),
    [
        (b"\x8b\x00", "invalid opcode"),
        (b"\xc1\x00", "RSV flags"),
        (b"\x09\x00", "FIN"),
        (b"\x89\x7e\x00\x7e" + b"x" * 126, "exceeds 125"),
        (b"\x88\x01\x00", "2-byte code"),
        (b"\x88\x02\x03\xed", "invalid close code"),
        (b"\x88\x03\x03\xe8\xff", "UTF-8"),
    ],
)
def test_parser_rejects_invalid_protocol_frames(raw_frame, message):
    from core.frame_parser import FrameProtocolError, parse_frame

    with pytest.raises(FrameProtocolError, match=message):
        parse_frame(raw_frame)


def test_parser_exposes_close_code_and_reason():
    from core.frame_builder import FrameBuilder
    from core.frame_parser import parse_frame

    raw_frame = FrameBuilder.build_frame(
        (1002).to_bytes(2, "big") + "protocol error".encode("utf-8"),
        opcode=FrameBuilder.OPCODE_CLOSE,
        mask=False,
    )
    frame, _ = parse_frame(raw_frame)

    assert frame.close_code == 1002
    assert frame.close_reason == "protocol error"


def test_parser_marks_ping_and_pong_as_control_frames():
    from core.frame_builder import FrameBuilder
    from core.frame_parser import parse_frame

    ping, _ = parse_frame(FrameBuilder.build_frame(b"ping", opcode=FrameBuilder.OPCODE_PING, mask=False))
    pong, _ = parse_frame(FrameBuilder.build_frame(b"pong", opcode=FrameBuilder.OPCODE_PONG, mask=False))

    assert ping.is_control and not ping.is_data
    assert pong.is_control and not pong.is_data


def test_connection_rejects_continuation_without_fragmented_message():
    from core.connection import WSConnection
    from core.frame_builder import FrameBuilder
    from core.frame_parser import FrameProtocolError

    class Socket:
        def recv(self, size):
            return FrameBuilder.build_frame(b"part", opcode=0, mask=False)

    connection = WSConnection("localhost", 80)
    connection.sock = Socket()

    with pytest.raises(FrameProtocolError, match="continuation"):
        connection.receive_frame()


def test_connection_accepts_fragmented_message_sequence():
    from core.connection import WSConnection
    from core.frame_builder import FrameBuilder

    frames = iter([
        FrameBuilder.build_frame(b"part", opcode=1, fin=False, mask=False),
        FrameBuilder.build_frame(b"end", opcode=0, fin=True, mask=False),
    ])

    class Socket:
        def recv(self, size):
            return next(frames)

    connection = WSConnection("localhost", 80)
    connection.sock = Socket()

    assert connection.receive_frame().fin is False
    assert connection.receive_frame().opcode == 0
