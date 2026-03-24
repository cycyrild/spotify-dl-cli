from collections.abc import Callable, Sequence
from unicorn.x86_const import (
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RSP,
    UC_X86_REG_RIP,
)
from unicorn import UC_HOOK_CODE
from unicorn.unicorn import Uc
import logging

logger = logging.getLogger(__name__)

HookCallback = Callable[[Uc, Sequence[int]], int | None]


def hook_amd64(mu: Uc, addr: int, callback: HookCallback):
    def _hook(mu: Uc, address: int, _size: int, _user_data: object):
        args = [
            mu.reg_read(UC_X86_REG_RCX),
            mu.reg_read(UC_X86_REG_RDX),
            mu.reg_read(UC_X86_REG_R8),
            mu.reg_read(UC_X86_REG_R9),
        ]

        rsp = mu.reg_read(UC_X86_REG_RSP)
        ret_addr = int.from_bytes(mu.mem_read(rsp, 8), "little")

        logger.debug("0x%X args=%s", address, args)

        result = callback(mu, args)

        mu.reg_write(UC_X86_REG_RAX, result if result is not None else 0)

        mu.reg_write(UC_X86_REG_RSP, rsp + 8)
        mu.reg_write(UC_X86_REG_RIP, ret_addr)

    mu.hook_add(UC_HOOK_CODE, _hook, begin=addr, end=addr)
