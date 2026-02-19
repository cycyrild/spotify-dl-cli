from typing import Callable

STUB_RET = bytes([0xC3])


# fmt: off
STUB_RET_ZERO = bytes([
    0x31, 0xC0,       # xor eax, eax
    0xC3              # ret
])

STUB_UNIQUE_LOCK_CTOR = bytes([
    0xC7, 0x01, 0x00, 0x00, 0x00, 0x00,  # mov dword ptr [ecx], 0
    0xC6, 0x41, 0x04, 0x00,              # mov byte ptr [ecx+4], 0
    0x8B, 0xC1,                          # mov eax, ecx
    0xC2, 0x04, 0x00                     # retn 4
])
# fmt: on


def _va_to_offset(image_base: int, image_size: int, va: int) -> int:
    off = va - image_base
    if off < 0 or off >= image_size:
        raise MemoryError("VA outside image")
    return off


def _write_bytes(image: bytearray, offset: int, data: bytes) -> None:
    if offset + len(data) > len(image):
        raise RuntimeError("patch crosses image boundary")
    image[offset : offset + len(data)] = data


def patch_ret(image: bytearray, image_base: int, va: int) -> None:
    off = _va_to_offset(image_base, len(image), va)
    _write_bytes(image, off, STUB_RET)


def patch_ret_zero(image: bytearray, image_base: int, va: int) -> None:
    off = _va_to_offset(image_base, len(image), va)
    _write_bytes(image, off, STUB_RET_ZERO)


def patch_unique_lock_ctor(image: bytearray, image_base: int, va: int) -> None:
    off = _va_to_offset(image_base, len(image), va)
    _write_bytes(image, off, STUB_UNIQUE_LOCK_CTOR)


PatchFn = Callable[[bytearray, int, int], None]

PATCHES: tuple[tuple[int, PatchFn], ...] = (
    (0x00463D65, patch_ret),  # __security_check_cookie
    (0x01022E27, patch_ret),  # thunk jmp -> ret
    (0x0100E345, patch_ret_zero),  # __Mtx_unlock
    (0x0100F8F6, patch_ret_zero),  # __Cnd_signal
    (0x0100F9DD, patch_ret_zero),  # __Cnd_wait
    (0x004EA215, patch_unique_lock_ctor),  # unique_lock ctor
)


def install_patches(image: bytearray, image_base: int) -> None:
    for va, fn in PATCHES:
        fn(image, image_base, va)
