from bisect import bisect_right
import logging
from typing import List, Optional, Tuple
from spotify_dl_cli.playplay_emulator5.emu.memory import (
    read_bytes,
    write_bytes,
    write_u64,
)
from spotify_dl_cli.playplay_emulator5.generated.runtimefunction_models import (
    HandlerType4,
    IPToStateEntry4,
    RuntimeFunction,
)
from spotify_dl_cli.playplay_emulator5.generated.throwinfo_models import CatchableType
from spotify_dl_cli.playplay_emulator5.seh.context import (
    apply_context_to_machine,
    capture_context_from_throw_entry,
    unwind_leaf_frame,
    unwind_nonleaf_frame,
)
from spotify_dl_cli.playplay_emulator5.seh.metadata import (
    catchable_type_descriptor_va,
    get_handler_data,
    get_ip_to_state_entries,
    handler_continuation_rva,
    iter_catchable_types,
    runtime_function_begin_va,
    runtime_function_end_va,
)
from spotify_dl_cli.playplay_emulator5.seh.registers import UnwindRegNum
from spotify_dl_cli.playplay_emulator5.seh.state import (
    SehRuntimeState,
    ThrownException,
    VirtualContext,
)
from unicorn.unicorn import Uc

MAX_UNWIND_DEPTH = 64
MAX_INLINE_CATCH_OBJECT_SIZE = 0x400

logger = logging.getLogger(__name__)


def lookup_runtime_function(
    state: SehRuntimeState, control_pc_va: int
) -> Optional[RuntimeFunction]:
    control_pc_rva = control_pc_va - state.image_base
    index = bisect_right(state.runtime_function_starts, control_pc_rva) - 1
    if index < 0:
        return None

    rf = state.runtime_functions[index]
    if control_pc_rva < rf.end_rva:
        return rf

    return None


def build_thrown_exception_from_static_data(
    state: SehRuntimeState, pExceptionObject: int, pThrowInfo: int
) -> ThrownException:
    throw_info_rva = pThrowInfo - state.image_base
    throw_info = state.throw_infos.get(throw_info_rva)

    if throw_info is None:
        raise RuntimeError(f"Unknown ThrowInfo RVA 0x{throw_info_rva:X}")

    return ThrownException(
        object_va=pExceptionObject, throw_info_va=pThrowInfo, throw_info=throw_info
    )


def lookup_ip_state(ip_to_state_map: List[IPToStateEntry4], control_pc_rva: int) -> int:
    state = -1
    for entry in ip_to_state_map:
        if control_pc_rva >= entry.ip:
            state = entry.state
        else:
            break
    return state


def find_matching_handler(
    state: SehRuntimeState,
    exc: ThrownException,
    rf: RuntimeFunction,
    control_pc_rva: int,
) -> Optional[Tuple[HandlerType4, Optional[CatchableType]]]:
    handler_data = get_handler_data(rf)
    if handler_data is None or handler_data.try_block_map is None:
        return None

    current_state = lookup_ip_state(get_ip_to_state_entries(rf), control_pc_rva)
    for tb in handler_data.try_block_map.try_blocks:
        if tb.try_low <= current_state <= tb.try_high:
            handler_map = tb.handler_map
            if handler_map is None:
                continue

            for handler in handler_map.handlers:
                if handler.disp_type is None:
                    return handler, None

                handler_type_va = state.image_base + handler.disp_type
                for ct in iter_catchable_types(exc.throw_info):
                    if (
                        catchable_type_descriptor_va(state.image_base, ct)
                        == handler_type_va
                    ):
                        return handler, ct

    return None


def materialize_catch_object(
    mu: Uc,
    ctx: VirtualContext,
    exc: ThrownException,
    handler: HandlerType4,
    ct: Optional[CatchableType],
):
    if handler.disp_catch_obj is None or ct is None:
        return

    dst = ctx.rsp + handler.disp_catch_obj
    src = exc.object_va + ct.mdisp
    size = ct.size_or_offset

    if 0 < size <= MAX_INLINE_CATCH_OBJECT_SIZE:
        write_bytes(mu, dst, read_bytes(mu, src, size))
    else:
        write_u64(mu, dst, src)


def dispatch_cpp_exception(
    state: SehRuntimeState, mu: Uc, pExceptionObject: int, pThrowInfo: int
) -> bool:
    exc: ThrownException = build_thrown_exception_from_static_data(
        state, pExceptionObject, pThrowInfo
    )
    ctx: VirtualContext = capture_context_from_throw_entry(mu)

    logger.debug("catchable types:")
    for ct in iter_catchable_types(exc.throw_info):
        logger.debug(
            "type_desc=0x%X mdisp=%d size=%d",
            catchable_type_descriptor_va(state.image_base, ct),
            ct.mdisp,
            ct.size_or_offset,
        )

    for _depth in range(MAX_UNWIND_DEPTH):
        control_pc = ctx.rip - 1 if ctx.rip > state.image_base else ctx.rip

        rf = lookup_runtime_function(state, control_pc)
        if rf is None:
            logger.debug(
                "no dumped metadata for 0x%X; treating frame as leaf", control_pc
            )
            unwind_leaf_frame(mu, ctx)
            continue

        logger.debug(
            "frame=0x%X-0x%X control_pc=0x%X",
            runtime_function_begin_va(state.image_base, rf),
            runtime_function_end_va(state.image_base, rf),
            control_pc,
        )

        matched = find_matching_handler(state, exc, rf, control_pc - state.image_base)
        if matched is not None:
            handler, ct = matched

            logger.debug("catch RVA 0x%X", handler.disp_of_handler)

            establisher_frame = ctx.rsp
            materialize_catch_object(mu, ctx, exc, handler, ct)

            ctx.rsp -= 8
            write_u64(
                mu, ctx.rsp, state.image_base + handler_continuation_rva(rf, handler)
            )

            ctx.regs[UnwindRegNum.RCX] = exc.object_va
            ctx.regs[UnwindRegNum.RDX] = establisher_frame
            ctx.rip = state.image_base + handler.disp_of_handler

            apply_context_to_machine(mu, ctx)
            return True

        unwind_nonleaf_frame(mu, ctx, rf)

    return False
