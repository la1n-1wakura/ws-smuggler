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
