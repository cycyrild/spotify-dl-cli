from typing import Any, TextIO, List, Tuple
from capstone import Cs


class CallTrace:
    def __init__(
        self,
        disassembler: Cs,
        trace_file: TextIO | None = None,
        enable_instr_log: bool = False,
    ) -> None:
        self.md = disassembler
        self.trace_file = trace_file
        self.enable_instr_log = enable_instr_log

    def hook(self, uc, address: int, size: int, user_data: Any) -> None:
        code = uc.mem_read(address, size)

        opcode_hex = code.hex()
        addr_hex = f"{address:08x}"

        if self.enable_instr_log and self.trace_file:
            line = f"i:{addr_hex}:{size}:{opcode_hex}"
            self.trace_file.write(line + "\n")
