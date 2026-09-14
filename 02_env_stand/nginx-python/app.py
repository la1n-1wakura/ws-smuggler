import asyncio
import websockets

# Обработчик WebSocket-соединений
# path - обязательный параметр для совместимости со старыми версиями библиотеки
async def echo(websocket, path):
    """
    Эхо-сервер: получает сообщение и отправляет его обратно с префиксом "Эхо: "
    """
    async for message in websocket:
        print(f"Получено: {message}")
        await websocket.send(f"Эхо: {message}")

async def main():
    """
    Запуск WebSocket-сервера на всех интерфейсах (0.0.0.0) на порту 5000
    """
    async with websockets.serve(echo, "0.0.0.0", 5000):
        print("=" * 50)
        print("🚀 WebSocket Echo Server запущен")
        print(f"📍 Адрес: 0.0.0.0:5000")
        print("=" * 50)
        print("Ожидание подключений...")
        # Бесконечное ожидание
        await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Сервер остановлен пользователем")
