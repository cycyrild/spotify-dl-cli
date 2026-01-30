import struct
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EBP
from unicorn.unicorn import Uc
from playplay_emulator.helpers import pack_u32


class UnicornStackUtils:
    def __init__(self, unicorn: Uc, stack_addr: int, stack_size: int) -> None:
        self.unicorn = unicorn
        self.stack_addr = stack_addr
        self.stack_size = stack_size

    def init_stack(self) -> int:
        esp = self.stack_addr + self.stack_size - 0x2000
        self.unicorn.reg_write(UC_X86_REG_ESP, esp)
        self.unicorn.reg_write(UC_X86_REG_EBP, esp)
        return esp

    def read_u32(self, addr: int) -> int:
        return struct.unpack("<I", self.unicorn.mem_read(addr, 4))[0]

    def write_u32(self, addr: int, value: int) -> None:
        self.unicorn.mem_write(addr, pack_u32(value))

    def write_stack_args(self, esp: int, *u32_values: int) -> None:
        for i, v in enumerate(u32_values):
            self.write_u32(esp + 4 * i, v)
