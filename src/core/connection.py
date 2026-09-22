# Управление TCP/SSL/Handshake сокетами

import socket
import ssl

class WSConnection:
    def __init__(self,  host: str, port: int, path: str = "/", use_ssl: bool = False):
        self.host = host
        self.port = port
        self.path = path
        self.use_ssl = use_ssl
        self.sock = None    # Здесь будет храниться наш открытый сокет

    def connect(self) -> str:
        """Открывает сокет и выполняет HTTP Upgrade Handshake"""
        # Создаем базовый TCP сокет
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Если цель защищена (wss://), оборачиваем сокет в SSL/TLS-шифрование
        if self.use_ssl:
            context = ssl.create_default_context()

            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            self.sock = context.wrap_socket(raw_sock, server_hostname=self.host)
        else:
            self.sock = raw_sock

        # Физически подключаемся к серверу
        self.sock.connect((self.host, self.port))

        # Формируем текст запроса на обновление протокола
        handshake = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )

        # Отправляем байты запроса в созданную трубу
        self.sock.sendall(handshake.encode('utf-8'))

        # Слушаем, что ответит сервер (ждем статус 101)
        response = self.sock.recv(4096)
        
        # Возвращаем текст ответа для проверки
        return response.decode('utf-8', errors='ignore')

    def close(self):
        """Закрываем сокет, когда закончили работу"""
        if self.sock:
            self.sock.close()