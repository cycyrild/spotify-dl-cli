from typing import Any, TextIO
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from unicorn import UC_MEM_READ, UC_MEM_WRITE, UC_MEM_FETCH
from unicorn.x86_const import UC_X86_REG_EIP


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

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        print(f"INVALID FETCH: addr=0x{address:08x} size={size}")
        return False
    
    def hook_block(self, uc, address, size, user_data):
        print(f"BB @ 0x{address:x}, size={size}")

    def hook_mem(
        self,
        uc,
        access: int,
        address: int,
        size: int,
        value: int,
        user_data: Any,
    ) -> None:
        addr_hex = f"{address:08x}"
        if access == UC_MEM_READ:
            self.trace_file.write(f"mr:{addr_hex}:{size}:{value:x}\n")
        elif access == UC_MEM_WRITE:
            self.trace_file.write(f"mw:{addr_hex}:{size}:{value:x}\n")
        elif access == UC_MEM_FETCH:
            self.trace_file.write(f"mf:{addr_hex}:{size}:{value:x}\n")
