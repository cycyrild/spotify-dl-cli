from .trace import InstructionTrace
from typing import Optional, TextIO
from unicorn.unicorn import Uc
from .constants import *
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_FETCH

"""
Debug-only helper that traces instructions and memory accesses during
Unicorn emulation. Not intended for performance-critical cases.
"""


def emu_with_trace(
    uc: Uc, start_addr: int, trace_file: TextIO | None, until: int = MAGIC_RET
) -> Optional[InstructionTrace]:
    shadow: Optional[InstructionTrace] = None
    hook_code = None
    hook_mem = None

    if trace_file is not None:
        shadow = InstructionTrace(trace_file)

        hook_code = uc.hook_add(UC_HOOK_CODE, shadow.hook_code)
        hook_mem = uc.hook_add(
            UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE | UC_HOOK_MEM_FETCH, shadow.hook_mem
        )
    try:
        uc.emu_start(begin=start_addr, until=until)
    finally:
        if hook_code is not None:
            uc.hook_del(hook_code)
        if hook_mem is not None:
            uc.hook_del(hook_mem)

    return shadow
