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
        self.stack: List[Tuple[int, int]] = []

    def hook(self, uc, address: int, size: int, user_data: Any) -> None:
        code = uc.mem_read(address, size)
        for ins in self.md.disasm(code, address):
            if self.enable_instr_log and self.trace_file:
                asm = f"0x{ins.address:08X}: {ins.mnemonic:<8} {ins.op_str}"
                self.trace_file.write(asm + "\n")

            if ins.mnemonic == "call":
                self.stack.append((ins.address, ins.address + ins.size))
            elif ins.mnemonic == "ret":
                if self.stack:
                    self.stack.pop()

    def dump(self) -> None:
        print("\n--- SHADOW CALL STACK ---")
        if not self.stack:
            print(" <empty>")
            return

        for i, (call, ret) in enumerate(reversed(self.stack)):
            print(f"#{i:02d} CALL @ 0x{call:08X} -> RET 0x{ret:08X}")

    def reset(self) -> None:
        self.stack.clear()
