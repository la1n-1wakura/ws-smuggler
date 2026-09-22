# Управление TCP/SSL/Handshake сокетами

import socket
import ssl
import base64
import hashlib
import secrets

from core.frame_parser import IncompleteFrameError, WebSocketFrame, parse_frame

class WSConnection:
    def __init__(self, host: str, port: int, path: str = "/", use_ssl: bool = False, timeout: float = 10.0, insecure: bool = False, ca_file: str | None = None):
        if insecure and ca_file is not None:
            raise ValueError("insecure and ca_file cannot be used together")

        self.host = host
        self.port = port
        self.path = path
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.insecure = insecure
        self.ca_file = ca_file
        self.sock = None    # Здесь будет храниться наш открытый сокет
        self._receive_buffer = bytearray()

    def _build_websocket_key(self) -> str:
        return base64.b64encode(secrets.token_bytes(16)).decode("ascii")

    def _expected_accept(self, websocket_key: str) -> str:
        magic = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        digest = hashlib.sha1(websocket_key.encode("ascii") + magic).digest()
        return base64.b64encode(digest).decode("ascii")

    def connect(self) -> str:
        """Открывает сокет и выполняет HTTP Upgrade Handshake"""
        if self.sock is not None:
            self.close()

        raw_sock = None
        try:
            # create_connection автоматически выбирает подходящий тип адреса (IPv4/IPv6)
            raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)

            # Если цель защищена (wss://), оборачиваем сокет в SSL/TLS-шифрование
            if self.use_ssl:
                if self.ca_file:
                    context = ssl.create_default_context(cafile=self.ca_file)
                else:
                    context = ssl.create_default_context()

                if self.insecure:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                self.sock = context.wrap_socket(raw_sock, server_hostname=self.host)
            else:
                self.sock = raw_sock

            self.sock.settimeout(self.timeout)
            self._receive_buffer.clear()

            websocket_key = self._build_websocket_key()
            expected_accept = self._expected_accept(websocket_key)

            # Формируем текст запроса на обновление протокола
            handshake = (
                f"GET {self.path} HTTP/1.1\r\n"
                f"Host: {self.host}:{self.port}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {websocket_key}\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "\r\n"
            )

            # Отправляем байты запроса в созданную трубу
            self.sock.sendall(handshake.encode('utf-8'))

            # Слушаем, что ответит сервер (ждем статус 101)
            buffer = b""
            while b"\r\n\r\n" not in buffer:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                buffer += chunk
                if len(buffer) > 65536:
                    raise TimeoutError("HTTP response header exceeded maximum size")

            response = buffer.decode('utf-8', errors='ignore')
            header_lines = response.split("\r\n")
            accept_value = None
            for line in header_lines:
                if line.lower().startswith("sec-websocket-accept:"):
                    accept_value = line.split(":", 1)[1].strip()
                    break

            if "101 Switching Protocols" not in response:
                return response

            if accept_value is None:
                raise ValueError("Server response missing Sec-WebSocket-Accept header")

            if accept_value != expected_accept:
                raise ValueError(
                    f"Invalid Sec-WebSocket-Accept header: expected {expected_accept}, got {accept_value}"
                )

            # Возвращаем текст ответа для проверки
            return response
        except Exception:
            if self.sock is not None:
                try:
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None
            if raw_sock is not None and raw_sock is not self.sock:
                try:
                    raw_sock.close()
                except Exception:
                    pass
            raise

    def close(self):
        """Закрываем сокет, когда закончили работу"""
        if self.sock:
            self.sock.close()
            self.sock = None
            self._receive_buffer.clear()

    def send_frame(self, frame: bytes) -> None:
        """Отправляет уже собранный WebSocket frame через активное соединение."""
        if self.sock is None:
            raise RuntimeError("WebSocket connection is not established")
        self.sock.sendall(frame)

    def receive(self, size: int = 4096) -> bytes:
        """Читает один фрагмент ответа сервера после handshake."""
        if self.sock is None:
            raise RuntimeError("WebSocket connection is not established")
        return self.sock.recv(size)

    def receive_frame(self) -> WebSocketFrame:
        """Считать из сокета ровно один полный WebSocket frame."""
        if self.sock is None:
            raise RuntimeError("WebSocket connection is not established")

        while True:
            try:
                frame, end = parse_frame(bytes(self._receive_buffer))
            except IncompleteFrameError:
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise ConnectionError("server closed connection before a complete frame")
                self._receive_buffer.extend(chunk)
                continue

            del self._receive_buffer[:end]
            return frame