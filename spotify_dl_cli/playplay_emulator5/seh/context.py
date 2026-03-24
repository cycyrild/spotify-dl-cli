from spotify_dl_cli.playplay_emulator5.emu.memory import read_u64
from spotify_dl_cli.playplay_emulator5.generated.runtimefunction_models import (
    RuntimeFunction,
    UWOP,
)
from spotify_dl_cli.playplay_emulator5.seh.registers import UNWIND_GPR_REGNUM_TO_UC
from spotify_dl_cli.playplay_emulator5.seh.state import VirtualContext
from unicorn.unicorn import Uc
from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RIP


def capture_context_from_throw_entry(mu: Uc) -> VirtualContext:
    """
    We hook _CxxThrowException at its entry.
    At that moment:
      [RSP] = return address into throw_ExcX
    So we skip the _CxxThrowException frame entirely.
    """
    rsp = mu.reg_read(UC_X86_REG_RSP)
    caller_rip = read_u64(mu, rsp)

    regs: dict[int, int] = {}
    for regnum, uc_reg in UNWIND_GPR_REGNUM_TO_UC.items():
        regs[regnum] = mu.reg_read(uc_reg)

    return VirtualContext(rip=caller_rip, rsp=rsp + 8, regs=regs)


def apply_context_to_machine(mu: Uc, ctx: VirtualContext):
    for regnum, uc_reg in UNWIND_GPR_REGNUM_TO_UC.items():
        mu.reg_write(uc_reg, ctx.regs.get(regnum, mu.reg_read(uc_reg)))

    mu.reg_write(UC_X86_REG_RSP, ctx.rsp)
    mu.reg_write(UC_X86_REG_RIP, ctx.rip)


def unwind_leaf_frame(mu: Uc, ctx: VirtualContext):
    ret = read_u64(mu, ctx.rsp)
    ctx.rsp += 8
    ctx.rip = ret


def unwind_nonleaf_frame(mu: Uc, ctx: VirtualContext, rf: RuntimeFunction):
    ui = rf.unwinds

    for op in ui.unwind_codes:
        if op.unwind_op == UWOP.PUSH_NONVOL:
            regnum = op.op_info
            value = read_u64(mu, ctx.rsp)
            ctx.set_reg(regnum, value)
            ctx.rsp += 8

        elif op.unwind_op == UWOP.ALLOC_LARGE:
            if op.extra is None:
                raise RuntimeError("UWOP_ALLOC_LARGE missing extra")
            ctx.rsp += op.extra

        elif op.unwind_op == UWOP.ALLOC_SMALL:
            ctx.rsp += (op.op_info * 8) + 8

        elif op.unwind_op == UWOP.SET_FPREG:
            fp_reg = ui.frame_register
            if fp_reg == 0:
                raise RuntimeError("UWOP_SET_FPREG with no frame register")
            ctx.rsp = ctx.get_reg(fp_reg) - (ui.frame_offset * 16)

        elif op.unwind_op == UWOP.SAVE_NONVOL:
            if op.extra is None:
                raise RuntimeError("UWOP_SAVE_NONVOL missing extra")
            ctx.set_reg(op.op_info, read_u64(mu, ctx.rsp + op.extra))

        elif op.unwind_op == UWOP.SAVE_NONVOL_FAR:
            if op.extra is None:
                raise RuntimeError("UWOP_SAVE_NONVOL_FAR missing extra")
            ctx.set_reg(op.op_info, read_u64(mu, ctx.rsp + op.extra))

        elif op.unwind_op == UWOP.SAVE_XMM128:
            pass

        elif op.unwind_op == UWOP.SAVE_XMM128_FAR:
            pass

        elif op.unwind_op == UWOP.PUSH_MACHFRAME:
            raise RuntimeError("UWOP_PUSH_MACHFRAME not supported in runtime unwind")

        else:
            raise RuntimeError(f"Unsupported unwind operation {op.unwind_op}")

    unwind_leaf_frame(mu, ctx)
