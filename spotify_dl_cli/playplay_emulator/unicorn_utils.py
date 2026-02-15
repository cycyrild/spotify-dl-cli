import struct
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EBP
from unicorn.unicorn import Uc


class UnicornStackUtils:
    def __init__(
        self,
        unicorn: Uc,
        stack_addr: int,
        stack_size: int,
        heap_addr: int,
        heap_size: int,
    ) -> None:
        self.unicorn = unicorn
        self.stack_addr = stack_addr
        self.stack_size = stack_size
        self.heap_addr = heap_addr
        self.heap_size = heap_size
        self._heap_cursor = 0

    def init_stack(self) -> int:
        esp = self.stack_addr + self.stack_size - 0x2000
        self.unicorn.reg_write(UC_X86_REG_ESP, esp)
        self.unicorn.reg_write(UC_X86_REG_EBP, esp)
        return esp

    def reset_heap(self) -> None:
        self._heap_cursor = 0

    def next_heap(self, size: int, align: int = 4) -> int:
        cur = (self._heap_cursor + (align - 1)) & ~(align - 1)
        end = cur + size
        if end > self.heap_size:
            raise MemoryError("heap overflow")

        addr = self.heap_addr + cur
        self._heap_cursor = end
        return addr

    def read_u32(self, addr: int) -> int:
        return struct.unpack("<I", self.unicorn.mem_read(addr, 4))[0]

    def write_u32(self, addr: int, value: int) -> None:
        self.unicorn.mem_write(addr, struct.pack("<I", value))

    def write_stack_args(self, esp: int, *args: int) -> None:
        for i, v in enumerate(args):
            self.write_u32(esp + 4 * i, v)
