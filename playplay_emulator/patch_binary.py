from __future__ import annotations
from typing import Iterable
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_RET

_MAX_SCAN = 0x400


def _va_to_off(image_base: int, image_size: int, va: int) -> int:
    off = va - image_base
    if off < 0 or off >= image_size:
        raise MemoryError(f"VA outside image: 0x{va:08X}")
    return off


def _extract_ret_bytes_from_image(
    image: bytes, image_base: int, func_va: int, md: Cs
) -> bytes:
    img_size = len(image)
    func_off = _va_to_off(image_base, img_size, func_va)

    scan_len = min(_MAX_SCAN, img_size - func_off)
    if scan_len <= 0:
        raise MemoryError(f"Invalid scan range at 0x{func_va:08X}")

    code = image[func_off : func_off + scan_len]

    for ins in md.disasm(code, func_va):
        if CS_GRP_RET in ins.groups:
            ins_off = _va_to_off(image_base, img_size, ins.address)
            return image[ins_off : ins_off + ins.size]

    raise ValueError(
        f"No RET instruction found within 0x{_MAX_SCAN:X} bytes from 0x{func_va:08X}"
    )


def install_stubs_in_image(
    image: bytearray, image_base: int, addresses: Iterable[int]
) -> None:
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    img_size = len(image)
    img_bytes = bytes(image)

    for va in addresses:
        stub = _extract_ret_bytes_from_image(img_bytes, image_base, va, md)

        off = _va_to_off(image_base, img_size, va)
        if off + len(stub) > img_size:
            raise MemoryError(f"Stub write crosses image boundary at 0x{va:08X}")

        image[off : off + len(stub)] = stub
