import struct


def pack_u32(value: int) -> bytes:
    return struct.pack("<I", value)
