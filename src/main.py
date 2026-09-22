# Точка входа (обработка аргументов CLI, запуск)
import argparse

from ui.shell import WSSmugglerShell
from ui.views import console, show_banner

def main():
    # 1. Создаем парсер аргументов командной строки
    parser = argparse.ArgumentParser(
        description="WS-Smuggler — Инструмент для низкоуровневого тестирования WebSockets"
    )

    # 2. Описываем, какие флаги мы ждем от пользователя
    parser.add_argument("--host", type=str, help="Целевой хост (например, echo.websocket.org)")
    parser.add_argument("--port", type=int, help="Порт сервера (например, 80 или 443)")
    parser.add_argument("--path", type=str, default="/", help="Путь для Upgrade Handshake (по умолчанию: /)")
    parser.add_argument("--ssl", action="store_true", help="Включить SSL/TLS (использовать wss://)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Таймаут подключения и чтения в секундах (по умолчанию: 10)")
    parser.add_argument("--insecure", action="store_true", help="Отключить проверку TLS-сертификата (только для лабораторного стенда)")
    parser.add_argument("--ca-file", type=str, help="Путь к доверенному CA-сертификату для проверки TLS")
    parser.add_argument("--manual", action="store_true", help="После handshake запустить ручную отправку WebSocket-фреймов")
    parser.add_argument("--log-traffic", action="store_true", help="Сохранять raw TX/RX, hex и PCAP в dumps/")

    # 3. Разбираем то, что ввел пользователь в терминале
    args = parser.parse_args()

    if args.insecure and args.ca_file:
        parser.error("--insecure и --ca-file нельзя использовать одновременно")
    if args.insecure and not args.ssl:
        parser.error("--insecure требует использования --ssl")
    if args.ca_file and not args.ssl:
        parser.error("--ca-file требует использования --ssl")

    show_banner()
    shell = WSSmugglerShell(
        host=args.host,
        port=args.port,
        path=args.path,
        use_ssl=args.ssl,
        timeout=args.timeout,
        insecure=args.insecure,
        ca_file=args.ca_file,
        initial_mode="manual",
        log_traffic=args.log_traffic,
    )
    shell.run(auto_connect=args.manual)

if __name__ == "__main__":
    main()