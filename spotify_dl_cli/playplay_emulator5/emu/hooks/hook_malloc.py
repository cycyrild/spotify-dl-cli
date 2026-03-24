import logging
from spotify_dl_cli.playplay_emulator5.emu.addressing import rebase
from spotify_dl_cli.playplay_emulator5.emu.heap_allocator import HeapAllocator
from unicorn.unicorn import Uc
from spotify_dl_cli.playplay_emulator5.emu.hooks.hook_amd64 import hook_amd64
from spotify_dl_cli.playplay_emulator5.consts import RT_HOOKS

logger = logging.getLogger(__name__)


def hook_malloc(mu: Uc, image_base: int, heap: HeapAllocator):
    addr = rebase(image_base, RT_HOOKS.MALLOC_VA)

    def _cb(mu: Uc, args):
        size = args[0]

        chunk = heap.alloc(size)

        logger.debug("size=0x%X -> 0x%X (chunk size=0x%X)", size, chunk.ptr, chunk.size)

        return chunk.ptr

    hook_amd64(mu, addr, _cb)

    logger.debug("j__malloc_base -> 0x%X", addr)
