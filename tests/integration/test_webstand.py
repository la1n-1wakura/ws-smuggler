import ssl
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from core.connection import WSConnection
from core.frame_builder import FrameBuilder


WEBSOCKET_STACKS = (
    pytest.param(8080, id="nginx-python"),
    pytest.param(8081, id="nginx-nodejs"),
    pytest.param(8082, id="haproxy-spring"),
)


@pytest.mark.integration
@pytest.mark.parametrize("port", WEBSOCKET_STACKS)
def test_webstand_stack_echo_and_close(port: int) -> None:
    host = "localhost"
    connection = WSConnection(
        host=host,
        port=port,
        path="/ws/",
        use_ssl=True,
        insecure=True,
        timeout=3.0,
    )

    try:
        try:
            response = connection.connect()
        except (ConnectionError, OSError, ssl.SSLError, TimeoutError) as error:
            pytest.skip(f"Docker WebStand is not running at {host}:{port}: {error}")

        assert response.startswith("HTTP/1.1 101 "), (
            f"WebStand at {host}:{port} returned an unexpected handshake: {response!r}"
        )

        payload = f"integration-test-{port}".encode("ascii")
        connection.send_frame(
            FrameBuilder.build_frame(
                payload,
                opcode=FrameBuilder.OPCODE_TEXT,
                fin=True,
                mask=True,
            )
        )
        echo = connection.receive_frame()

        assert echo.opcode == FrameBuilder.OPCODE_TEXT
        assert echo.fin is True
        assert echo.masked is False
        assert echo.payload == b"\xd0\xad\xd1\x85\xd0\xbe: " + payload

        connection.send_frame(
            FrameBuilder.build_frame(
                (1000).to_bytes(2, "big"),
                opcode=FrameBuilder.OPCODE_CLOSE,
                fin=True,
                mask=True,
            )
        )
        close_response = connection.receive_frame()

        assert close_response.opcode == FrameBuilder.OPCODE_CLOSE
        assert close_response.fin is True
        assert close_response.payload[:2] == (1000).to_bytes(2, "big")
    finally:
        connection.close()