"""Разбор WebSocket-фреймов RFC 6455."""

from dataclasses import dataclass


class IncompleteFrameError(ValueError):
    """Недостаточно байт для полного WebSocket-фрейма."""


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
    return frame, end
