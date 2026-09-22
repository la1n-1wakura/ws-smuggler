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
