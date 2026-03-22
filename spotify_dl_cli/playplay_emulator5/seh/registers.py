from enum import IntEnum

from unicorn.x86_const import (
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_R10,
    UC_X86_REG_R11,
    UC_X86_REG_R12,
    UC_X86_REG_R13,
    UC_X86_REG_R14,
    UC_X86_REG_R15,
    UC_X86_REG_RAX,
    UC_X86_REG_RBP,
    UC_X86_REG_RBX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDI,
    UC_X86_REG_RDX,
    UC_X86_REG_RSI,
)


class UnwindRegNum(IntEnum):
    RAX = 0
    RCX = 1
    RDX = 2
    RBX = 3
    RSP = 4
    RBP = 5
    RSI = 6
    RDI = 7
    R8 = 8
    R9 = 9
    R10 = 10
    R11 = 11
    R12 = 12
    R13 = 13
    R14 = 14
    R15 = 15


UNWIND_GPR_REGNUM_TO_UC = {
    UnwindRegNum.RAX: UC_X86_REG_RAX,
    UnwindRegNum.RCX: UC_X86_REG_RCX,
    UnwindRegNum.RDX: UC_X86_REG_RDX,
    UnwindRegNum.RBX: UC_X86_REG_RBX,
    UnwindRegNum.RBP: UC_X86_REG_RBP,
    UnwindRegNum.RSI: UC_X86_REG_RSI,
    UnwindRegNum.RDI: UC_X86_REG_RDI,
    UnwindRegNum.R8: UC_X86_REG_R8,
    UnwindRegNum.R9: UC_X86_REG_R9,
    UnwindRegNum.R10: UC_X86_REG_R10,
    UnwindRegNum.R11: UC_X86_REG_R11,
    UnwindRegNum.R12: UC_X86_REG_R12,
    UnwindRegNum.R13: UC_X86_REG_R13,
    UnwindRegNum.R14: UC_X86_REG_R14,
    UnwindRegNum.R15: UC_X86_REG_R15,
}
