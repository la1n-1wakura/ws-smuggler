"""Разбор WebSocket-фреймов RFC 6455."""

from dataclasses import dataclass


class IncompleteFrameError(ValueError):
    """Недостаточно байт для полного WebSocket-фрейма."""


class FrameProtocolError(ValueError):
	"""Нарушение структурного правила RFC 6455 во входящем frame."""


@dataclass(frozen=True)
class WebSocketFrame:
    fin: bool
    rsv1: bool
    rsv2: bool
    rsv3: bool
    opcode: int
    masked: bool
    payload: bytes
    header_length: int

    @property
    def total_length(self) -> int:
        return self.header_length + len(self.payload)

    @property
    def is_control(self) -> bool:
        return self.opcode >= 0x8

    @property
    def is_data(self) -> bool:
        return self.opcode in {0x0, 0x1, 0x2}

    @property
    def close_code(self) -> int | None:
        if self.opcode != 0x8 or len(self.payload) < 2:
            return None
        return int.from_bytes(self.payload[:2], "big")

    @property
    def close_reason(self) -> str:
        if self.opcode != 0x8 or len(self.payload) <= 2:
            return ""
        return self.payload[2:].decode("utf-8", errors="replace")


def _validate_close_payload(payload: bytes) -> None:
    if len(payload) == 1:
        raise FrameProtocolError("close frame payload must be empty or contain a 2-byte code")
    if len(payload) < 2:
        return
    code = int.from_bytes(payload[:2], "big")
    valid_codes = {1000, 1001, 1002, 1003, *range(1007, 1015)}
    if code not in valid_codes:
        raise FrameProtocolError(f"invalid close code: {code}")
    try:
        payload[2:].decode("utf-8")
    except UnicodeDecodeError as error:
        raise FrameProtocolError("close reason is not valid UTF-8") from error


def validate_frame(frame: WebSocketFrame) -> None:
    """Проверить правила, не зависящие от предыдущих frame-ов."""
    if frame.opcode not in {0x0, 0x1, 0x2, 0x8, 0x9, 0xA}:
        raise FrameProtocolError(f"invalid opcode: 0x{frame.opcode:x}")
    if frame.rsv1 or frame.rsv2 or frame.rsv3:
        raise FrameProtocolError("RSV flags are set without a negotiated extension")
    if frame.is_control:
        if not frame.fin:
            raise FrameProtocolError("control frames must have FIN set")
        if len(frame.payload) > 125:
            raise FrameProtocolError("control frame payload exceeds 125 bytes")
        if frame.opcode == 0x8:
            _validate_close_payload(frame.payload)


def parse_frame(data: bytes, offset: int = 0) -> tuple[WebSocketFrame, int]:
    """Разобрать один frame и вернуть frame вместе с позицией после него."""
    if offset < 0 or offset > len(data):
        raise ValueError("offset is outside data")
    if len(data) - offset < 2:
        raise IncompleteFrameError("frame header requires 2 bytes")

    first_byte = data[offset]
    second_byte = data[offset + 1]
    fin = bool(first_byte & 0x80)
    rsv1 = bool(first_byte & 0x40)
    rsv2 = bool(first_byte & 0x20)
    rsv3 = bool(first_byte & 0x10)
    opcode = first_byte & 0x0F
    masked = bool(second_byte & 0x80)
    length_code = second_byte & 0x7F
    position = offset + 2

    if length_code < 126:
        payload_length = length_code
    elif length_code == 126:
        if len(data) - position < 2:
            raise IncompleteFrameError("extended 16-bit length is incomplete")
        payload_length = int.from_bytes(data[position:position + 2], "big")
        position += 2
    else:
        if len(data) - position < 8:
            raise IncompleteFrameError("extended 64-bit length is incomplete")
        payload_length = int.from_bytes(data[position:position + 8], "big")
        position += 8
        if payload_length & (1 << 63):
            raise ValueError("64-bit payload length has an invalid high bit")

    masking_key = b""
    if masked:
        if len(data) - position < 4:
            raise IncompleteFrameError("masking key is incomplete")
        masking_key = data[position:position + 4]
        position += 4

    end = position + payload_length
    if len(data) < end:
        raise IncompleteFrameError("payload is incomplete")

    payload = data[position:end]
    if masked:
        payload = bytes(value ^ masking_key[index % 4] for index, value in enumerate(payload))

    frame = WebSocketFrame(
        fin=fin,
        rsv1=rsv1,
        rsv2=rsv2,
        rsv3=rsv3,
        opcode=opcode,
        masked=masked,
        payload=payload,
        header_length=position - offset,
    )
    validate_frame(frame)
    return frame, end
