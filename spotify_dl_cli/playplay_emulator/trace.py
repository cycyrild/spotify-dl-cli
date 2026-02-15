from typing import Any, TextIO
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from unicorn import UC_MEM_READ, UC_MEM_WRITE, UC_MEM_FETCH
from unicorn.x86_const import (
    UC_X86_REG_EAX,
    UC_X86_REG_EBX,
    UC_X86_REG_ECX,
    UC_X86_REG_EDX,
    UC_X86_REG_ESI,
    UC_X86_REG_EDI,
    UC_X86_REG_EBP,
    UC_X86_REG_ESP,
    UC_X86_REG_EIP,
    UC_X86_REG_EFLAGS,
)

"""
Intended for emulator debugging purposes
"""


class InstructionTrace:
    def __init__(self, trace_file: TextIO) -> None:
        self.trace_file = trace_file
        self.disasm = Cs(CS_ARCH_X86, CS_MODE_32)

    def hook_code(self, uc, address: int, size: int, user_data: Any) -> None:
        addr_hex = f"{address:08x}"
        code = uc.mem_read(address, size)

        asm_str = "invalid"
        for insn in self.disasm.disasm(code, address, count=1):
            asm_str = f"{insn.mnemonic} {insn.op_str}".strip()
            break

        opcode_hex = code.hex()
        self.trace_file.write(f"i:{addr_hex}:{size}:{opcode_hex}:{asm_str}\n")

        eax = uc.reg_read(UC_X86_REG_EAX)
        ebx = uc.reg_read(UC_X86_REG_EBX)
        ecx = uc.reg_read(UC_X86_REG_ECX)
        edx = uc.reg_read(UC_X86_REG_EDX)
        esi = uc.reg_read(UC_X86_REG_ESI)
        edi = uc.reg_read(UC_X86_REG_EDI)
        ebp = uc.reg_read(UC_X86_REG_EBP)
        esp = uc.reg_read(UC_X86_REG_ESP)
        eip = uc.reg_read(UC_X86_REG_EIP)
        eflags = uc.reg_read(UC_X86_REG_EFLAGS)

        self.trace_file.write(
            f"r:{eax:08x}:{ebx:08x}:{ecx:08x}:{edx:08x}:"
            f"{esi:08x}:{edi:08x}:{ebp:08x}:{esp:08x}:{eip:08x}:{eflags:08x}\n"
        )

    def hook_mem(
        self, uc, access: int, address: int, size: int, value: int, user_data: Any
    ) -> None:
        addr_hex = f"{address:08x}"
        if access == UC_MEM_READ:
            self.trace_file.write(f"mr:{addr_hex}:{size}:{value:x}\n")
        elif access == UC_MEM_WRITE:
            self.trace_file.write(f"mw:{addr_hex}:{size}:{value:x}\n")
        elif access == UC_MEM_FETCH:
            self.trace_file.write(f"mf:{addr_hex}:{size}:{value:x}\n")
