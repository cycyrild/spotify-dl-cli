from pathlib import Path
from unicorn import UC_HOOK_CODE
from unicorn.unicorn import Uc
from unicorn.x86_const import (
    UC_X86_REG_RAX,
    UC_X86_REG_RBX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_RSI,
    UC_X86_REG_RDI,
    UC_X86_REG_RSP,
    UC_X86_REG_RBP,
)
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CsInsn


class TraceLogger:
    def __init__(self, path: Path, image_base: int):
        self.image_base = image_base
        self.log_file = open(path, "w")

        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True

        self._mu: Uc | None = None
        self._hook = None

    def attach(self, mu: Uc):
        self._mu = mu
        self._hook = mu.hook_add(UC_HOOK_CODE, self._hook_code)

    def stop(self):
        if self._mu is None or self._hook is None:
            raise RuntimeError("TraceLogger.stop() called while not attached")

        self._mu.hook_del(self._hook)

        self._hook = None
        self._mu = None

        if self.log_file:
            self.log_file.close()
            self.log_file = None

    def _hook_code(self, mu: Uc, address: int, size: int, user_data):
        if not self.log_file:
            return

        code = mu.mem_read(address, size)

        for insn in self.md.disasm(code, address):
            regs = self._read_registers(mu)
            line = self._format_trace_line(insn, regs)
            self.log_file.write(line)

    def _read_registers(self, mu: Uc):
        return {
            "RAX": mu.reg_read(UC_X86_REG_RAX),
            "RBX": mu.reg_read(UC_X86_REG_RBX),
            "RCX": mu.reg_read(UC_X86_REG_RCX),
            "RDX": mu.reg_read(UC_X86_REG_RDX),
            "RSI": mu.reg_read(UC_X86_REG_RSI),
            "RDI": mu.reg_read(UC_X86_REG_RDI),
            "RSP": mu.reg_read(UC_X86_REG_RSP),
            "RBP": mu.reg_read(UC_X86_REG_RBP),
        }

    def _format_trace_line(self, insn: CsInsn, regs: dict[str, int]):
        rel = insn.address - self.image_base
        return (
            f"0x{rel:016X} | "
            f"{insn.mnemonic:6} {insn.op_str:20} | "
            f"RAX={regs['RAX']:016X} RBX={regs['RBX']:016X} "
            f"RCX={regs['RCX']:016X} RDX={regs['RDX']:016X} "
            f"RSI={regs['RSI']:016X} RDI={regs['RDI']:016X} "
            f"RSP={regs['RSP']:016X} RBP={regs['RBP']:016X}\n"
        )
