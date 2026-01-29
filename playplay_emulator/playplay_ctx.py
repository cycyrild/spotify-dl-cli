import ctypes

class PlayPlayCtx(ctypes.Structure):
    _fields_ = [
        ("initialized", ctypes.c_uint8),
        ("pad0", ctypes.c_uint8 * 3),
        ("state", ctypes.c_uint8 * 744),
        ("keystream", ctypes.c_uint8 * 16),
        ("block_index", ctypes.c_uint32),
        ("setup_value", ctypes.c_uint32),
        ("ready_flag", ctypes.c_uint32),
    ]

    @classmethod
    def from_bytes(cls, data: bytes) -> "PlayPlayCtx":
        if len(data) != ctypes.sizeof(cls):
            raise ValueError(
                f"Invalid buffer size: {len(data)} != {ctypes.sizeof(cls)}"
            )

        obj = cls()
        ctypes.memmove(
            ctypes.addressof(obj),
            data,
            ctypes.sizeof(cls),
        )
        return obj

    @classmethod
    def size(cls) -> int:
        return ctypes.sizeof(cls)
    
    def to_bytes(self) -> bytes:
        return ctypes.string_at(
            ctypes.addressof(self),
            ctypes.sizeof(self),
        )

assert ctypes.sizeof(PlayPlayCtx) == 0x308
