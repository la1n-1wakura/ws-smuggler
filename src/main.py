# Точка входа (обработка аргументов CLI, запуск)
import argparse
import sys

from core.connection import WSConnection

def main():
    # 1. Создаем парсер аргументов командной строки
    parser = argparse.ArgumentParser(
        description="WS-Smuggler — Инструмент для низкоуровневого тестирования WebSockets"
    )

    # 2. Описываем, какие флаги мы ждем от пользователя
    parser.add_argument("--host", type=str, required=True, help="Целевой хост (например, echo.websocket.org)")
    parser.add_argument("--port", type=int, required=True, help="Порт сервера (например, 80 или 443)")
    parser.add_argument("--path", type=str, default="/", help="Путь для Upgrade Handshake (по умолчанию: /)")
    parser.add_argument("--ssl", action="store_true", help="Включить SSL/TLS (использовать wss://)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Таймаут подключения и чтения в секундах (по умолчанию: 10)")
    parser.add_argument("--insecure", action="store_true", help="Отключить проверку TLS-сертификата (только для лабораторного стенда)")
    parser.add_argument("--ca-file", type=str, help="Путь к доверенному CA-сертификату для проверки TLS")

    # 3. Разбираем то, что ввел пользователь в терминале
    args = parser.parse_args()

    if args.insecure and args.ca_file:
        parser.error("--insecure и --ca-file нельзя использовать одновременно")
    if args.ca_file and not args.ssl:
        parser.error("--ca-file требует использования --ssl")

    print(f"[*] Инициализация подключения к {args.host}:{args.port}{args.path} (SSL: {args.ssl})")

    # 4. Передаем полученные аргументы в наш класс 
    connection = WSConnection(
        host=args.host,
        port=args.port,
        path=args.path,
        use_ssl=args.ssl,
        timeout=args.timeout,
        insecure=args.insecure,
        ca_file=args.ca_file
    )

    try:
        # 5. Пытаемся подключиться и выполнить Handshake
        print("[*] Отправка HTTP Upgrade Handshake...")
        handshake_response = connection.connect()
        
        # Выводим то, что ответил сервер
        print("\n[+] Ответ сервера:")
        print("-" * 40)
        print(handshake_response)
        print("-" * 40)
        
        if "101 Switching Protocols" in handshake_response:
            print("[+] Успех! Соединение переключено на WebSocket и готово к отправке кадров.")
        else:
            print("[-] Сервер отклонил Upgrade запрос (Статус не 101).")

    except Exception as e:
        print(f"[!] Ошибка при подключении: {e}")
        sys.exit(1)
        
    finally:
        # 6. В конце всегда закрываем сокет
        connection.close()
        print("[*] Соединение закрыто.")

if __name__ == "__main__":
    main()