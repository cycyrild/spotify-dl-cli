import logging
from spotify_dl_cli.playplay_emulator5.emu.addressing import rebase
from unicorn.unicorn import Uc
from spotify_dl_cli.playplay_emulator5.consts import RT_HOOKS

logger = logging.getLogger(__name__)


def stub_patches(mu: Uc, image_base: int):
    def patch_ret0(mu: Uc, addr: int, size: int = 8):
        stub = b"\x31\xc0\xc3"  # xor eax, eax; ret
        if size < len(stub):
            raise ValueError("Patch size too small")
        mu.mem_write(addr, stub + b"\x90" * (size - len(stub)))

    targets = {
        "_Mtx_lock": RT_HOOKS.MTX_LOCK_VA,
        "_Cnd_wait": RT_HOOKS.CND_WAIT_VA,
        "_Mtx_unlock": RT_HOOKS.MTX_UNLOCK_VA,
    }

    for name, ida_va in targets.items():
        addr = rebase(image_base, ida_va)
        patch_ret0(mu, addr, size=3)
        logger.debug("%s -> 0x%X", name, addr)
