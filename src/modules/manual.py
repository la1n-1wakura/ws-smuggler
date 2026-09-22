"""Интерактивная отправка вручную собранных WebSocket-фреймов."""

from core.connection import WSConnection
from core.frame_builder import FrameBuilder


def _read_bool(prompt: str, default: bool) -> bool:
	suffix = "Y/n" if default else "y/N"
	value = input(f"{prompt} [{suffix}]: ").strip().lower()
	if not value:
		return default
	if value in {"y", "yes", "д", "да", "1"}:
		return True
	if value in {"n", "no", "н", "нет", "0"}:
		return False
	raise ValueError("ожидалось yes/no")


def run_manual_mode(connection: WSConnection) -> None:
	"""Запускает цикл ввода и отправки кадров по активному соединению."""
	print("[*] Ручной режим. Для выхода введите :quit вместо payload.")

	while True:
		payload_text = input("payload> ")
		if payload_text == ":quit":
			return

		opcode = int(input("opcode [1=text, 2=binary, 8=close, 9=ping, 10=pong] [1]: ") or "1", 0)
		fin = _read_bool("FIN", True)
		mask = _read_bool("Mask", True)
		custom_length_text = input("custom_length [Enter = фактическая длина]: ").strip()
		custom_length = int(custom_length_text, 0) if custom_length_text else None

		frame = FrameBuilder.build_frame(
			payload_text.encode("utf-8"),
			opcode=opcode,
			fin=fin,
			mask=mask,
			custom_length=custom_length,
		)
		connection.send_frame(frame)
		print(f"[>] Отправлено байт: {len(frame)}")

		response = connection.receive()
		if not response:
			print("[!] Сервер закрыл соединение")
			return
		print(f"[<] Получено байт: {len(response)}: {response.hex(' ')}")
