import struct
from collections.abc import Sequence
from unicorn.unicorn import Uc
from spotify_dl_cli.playplay_emulator5.consts import MEM
from spotify_dl_cli.playplay_emulator5.emu.addressing import align
from unicorn.x86_const import (
    UC_X86_REG_GS_BASE,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_RSP,
)


def setup_stack(mu: Uc):
    mu.mem_map(MEM.STACK_ADDR, align(MEM.STACK_SIZE))
    mu.reg_write(UC_X86_REG_RSP, MEM.STACK_ADDR + MEM.STACK_SIZE)


def setup_teb(mu: Uc):
    mu.mem_map(MEM.TEB_ADDR, MEM.PAGE_SIZE)
    mu.reg_write(UC_X86_REG_GS_BASE, MEM.TEB_ADDR)


def emulate_call(mu: Uc, func: int, args: Sequence[int]):
    original_rsp = mu.reg_read(UC_X86_REG_RSP)
    rsp = mu.reg_read(UC_X86_REG_RSP)

    # Windows x64 ABI:
    # - 0x20 bytes of shadow space
    # - synthetic return address
    # Result: at callee entry, RSP % 16 == 8, same as a real CALL.
    rsp -= 0x20
    rsp -= 8

    mu.mem_write(rsp, struct.pack("<Q", MEM.EXIT_ADDR))
    mu.reg_write(UC_X86_REG_RSP, rsp)

    regs = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
    for index, arg in enumerate(args[:4]):
        mu.reg_write(regs[index], arg)

    mu.emu_start(func, MEM.EXIT_ADDR)
    mu.reg_write(UC_X86_REG_RSP, original_rsp)
