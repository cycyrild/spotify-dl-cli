import logging
from spotify_dl_cli.playplay_emulator5.seh.dispatcher import dispatch_cpp_exception
from spotify_dl_cli.playplay_emulator5.seh.state import SehRuntimeState
from unicorn import UC_HOOK_CODE
from unicorn.unicorn import Uc
from unicorn.x86_const import (
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_RIP,
    UC_X86_REG_RSP,
)

logger = logging.getLogger(__name__)


def install_seh_hook(mu: Uc, state: SehRuntimeState) -> None:
    logger.debug("image base            : 0x%X", state.image_base)
    logger.debug("_CxxThrowException   : 0x%X", state.cxx_throw_exception)
    logger.debug("dumped functions     : %d", len(state.runtime_functions))
    logger.debug("dumped throw infos   : %d", len(state.throw_infos))

    mu.hook_add(
        UC_HOOK_CODE,
        hook_code,
        state,
        begin=state.cxx_throw_exception,
        end=state.cxx_throw_exception,
    )


def hook_code(mu: Uc, address: int, size: int, state: SehRuntimeState):
    if address != state.cxx_throw_exception:
        return

    pExceptionObject = mu.reg_read(UC_X86_REG_RCX)
    pThrowInfo = mu.reg_read(UC_X86_REG_RDX)

    logger.debug("=== CxxThrowException ===")
    logger.debug("VA: 0x%X", address)
    logger.debug("RVA: 0x%X", address - state.image_base)
    logger.debug("pExceptionObject: 0x%X", pExceptionObject)
    logger.debug("pThrowInfo: 0x%X", pThrowInfo)

    try:
        handled = dispatch_cpp_exception(state, mu, pExceptionObject, pThrowInfo)
    except Exception as exc:
        logger.error("dispatch error: %s", exc)
        raise

    if handled:
        logger.debug("exception handled")
        logger.debug("new RIP: 0x%X", mu.reg_read(UC_X86_REG_RIP))
        logger.debug("new RSP: 0x%X", mu.reg_read(UC_X86_REG_RSP))
        return

    raise RuntimeError("Unhandled C++ exception in Unicorn dispatcher")
