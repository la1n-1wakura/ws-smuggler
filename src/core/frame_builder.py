# Сборка кастомных и поврежденных кадров (RFC 6455)

import os
from typing import Optional


class FrameBuilder:
    OPCODE_TEXT = 0x1
    OPCODE_BINARY = 0x2
    OPCODE_CLOSE = 0x8
    OPCODE_PING = 0x9
    OPCODE_PONG = 0xA

    @staticmethod
    def _mask_payload(payload: bytes, masking_key: bytes) -> bytes:
        if len(masking_key) != 4:
            raise ValueError("masking key must be 4 bytes")
        return bytes(b ^ masking_key[i % 4] for i, b in enumerate(payload))

    @staticmethod
    def build_frame(
        payload: bytes,
        opcode: int = 0x1,
        fin: bool = True,
        rsv1: bool = False,
        rsv2: bool = False,
        rsv3: bool = False,
        mask: bool = True,
        custom_length: Optional[int] = None,
        masking_key: Optional[bytes] = None,
    ) -> bytes:
        if not 0 <= opcode <= 0xF:
            raise ValueError("opcode must be in range 0x0-0xF")

        if masking_key is None:
            masking_key = os.urandom(4)

        payload_bytes = bytes(payload)
        declared_length = len(payload_bytes) if custom_length is None else custom_length

        if declared_length < 0:
            raise ValueError("custom_length cannot be negative")
        if opcode >= 0x8 and (not fin or declared_length > 125):
            raise ValueError("control frames must be FIN and have declared length <= 125")

        first_byte = 0x00
        if fin:
            first_byte |= 0x80
        if rsv1:
            first_byte |= 0x40
        if rsv2:
            first_byte |= 0x20
        if rsv3:
            first_byte |= 0x10
        first_byte |= opcode & 0x0F

        second_byte = 0x00
        if mask:
            second_byte |= 0x80

        if declared_length < 126:
            second_byte |= declared_length & 0x7F
            header = bytes([first_byte, second_byte])
        elif declared_length <= 0xFFFF:
            second_byte |= 126
            header = bytes([first_byte, second_byte]) + declared_length.to_bytes(2, byteorder="big")
        else:
            second_byte |= 127
            header = bytes([first_byte, second_byte]) + declared_length.to_bytes(8, byteorder="big")

        if mask:
            masked_payload = FrameBuilder._mask_payload(payload_bytes, masking_key)
            return header + masking_key + masked_payload
        return header + payload_bytes
