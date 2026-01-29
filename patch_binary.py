from __future__ import annotations

from typing import Iterable

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_RET
from unicorn.unicorn import Uc

_MAX_SCAN = 0x400


def _find_region_end(uc: Uc, addr: int) -> int:
    for start, end, _perms in uc.mem_regions():
        if start <= addr < end:
            return end
    raise MemoryError(f"Address not mapped: 0x{addr:08X}")


def _extract_ret_bytes(uc: Uc, md: Cs, func_addr: int) -> bytes:
    region_end = _find_region_end(uc, func_addr)
    scan_len = min(_MAX_SCAN, region_end - func_addr)
    if scan_len <= 0:
        raise MemoryError(f"Invalid scan range at 0x{func_addr:08X}")

    code = uc.mem_read(func_addr, scan_len)

    for ins in md.disasm(code, func_addr):
        if CS_GRP_RET in ins.groups:
            return bytes(uc.mem_read(ins.address, ins.size))

    raise ValueError(
        f"No RET instruction found within 0x{_MAX_SCAN:X} bytes from 0x{func_addr:08X}"
    )


def install_stubs(uc: Uc, addresses: Iterable[int]) -> None:
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    for addr in addresses:
        stub = _extract_ret_bytes(uc, md, addr)

        region_end = _find_region_end(uc, addr)
        if addr + len(stub) > region_end:
            raise MemoryError(f"Stub write crosses region boundary at 0x{addr:08X}")

        uc.mem_write(addr, stub)
