import logging
from spotify_dl_cli.playplay_emulator5.emu.hooks.stub_patches import stub_patches
from spotify_dl_cli.playplay_emulator5.emu.hooks.hook_malloc import hook_malloc
from pefile import PE
from unicorn import UC_ARCH_X86, UC_MODE_64
from unicorn.unicorn import Uc
from spotify_dl_cli.playplay_emulator5.consts import (
    EMULATOR_SIZES,
    MEM,
    PATHS,
    PLAYPLAY_TOKEN,
    RT_FUNCTIONS,
    RT_DATA,
)
from spotify_dl_cli.playplay_emulator5.emu import runtime
from spotify_dl_cli.playplay_emulator5.emu.addressing import rebase
from spotify_dl_cli.playplay_emulator5.emu.heap_allocator import HeapAllocator
from spotify_dl_cli.playplay_emulator5.seh import seh_hook
from spotify_dl_cli.playplay_emulator5.emu.map_pe import map_pe
from pathlib import Path
import struct

logger = logging.getLogger(__name__)


class KeyEmu:
    def __init__(self, sp_client_path: Path) -> None:
        self._mu = Uc(UC_ARCH_X86, UC_MODE_64)

        self._pe = PE(sp_client_path, fast_load=True)
        self._image_base, self._image_size = map_pe(self._mu, self._pe)

        logger.debug(
            "PE mapped at 0x%X with size 0x%X", self._image_base, self._image_size
        )

        seh_hook.install(
            self._mu,
            self._image_base,
            PATHS.RUNTIME_FUNCTIONS_JSON,
            PATHS.THROW_INFOS_JSON,
        )

        self._heap = HeapAllocator.create(self._mu, MEM.HEAP_ADDR, MEM.HEAP_SIZE)

        stub_patches(self._mu, self._image_base)
        hook_malloc(self._mu, self._image_base, self._heap)

        runtime.setup_stack(self._mu)
        runtime.setup_teb(self._mu)

        self._vm_runtime_init = rebase(
            self._image_base, RT_FUNCTIONS.VM_RUNTIME_INIT_VA
        )
        self._vm_object_transform = rebase(
            self._image_base, RT_FUNCTIONS.VM_OBJECT_TRANSFORM_VA
        )
        self._initWithKey = rebase(self._image_base, RT_FUNCTIONS.INIT_WITH_KEY_VA)
        self._generateKeystream = rebase(
            self._image_base, RT_FUNCTIONS.GENERATE_KEYSTREAM_VA
        )

        self._vmObj = self._heap.alloc(EMULATOR_SIZES.VM_OBJECT)
        self._obfuscatedKey = self._heap.alloc(EMULATOR_SIZES.OBFUSCATED_KEY)
        self._contentId = self._heap.alloc(EMULATOR_SIZES.CONTENT_ID)
        self._derivedKey = self._heap.alloc(EMULATOR_SIZES.DERIVED_KEY)
        self._state = self._heap.alloc(EMULATOR_SIZES.STATE)
        self._out_word = self._heap.alloc(EMULATOR_SIZES.WORD)
        self._keyStream = self._heap.alloc(EMULATOR_SIZES.KEY)

        self._playplay_token: bytearray | None = None

        self._init_runtime()

    def _init_runtime(self):
        rt_context = self._heap.alloc(0x10)
        data = bytearray(rt_context.size)
        struct.pack_into(
            "<Q", data, 8, rebase(self._image_base, RT_DATA.RUNTIME_CONTEXT_VA)
        )
        rt_context.write(bytes(data))

        runtime.emulate_call(
            self._mu, self._vm_runtime_init, [self._vmObj.ptr(), rt_context.ptr(), 1]
        )

    def _read_playplay_token(self) -> bytearray:
        addr = rebase(self._image_base, PLAYPLAY_TOKEN.VA)
        return self._mu.mem_read(addr, PLAYPLAY_TOKEN.SIZE)

    @property
    def playplay_token(self) -> bytearray:
        if self._playplay_token is None:
            self._playplay_token = self._read_playplay_token()
        return self._playplay_token

    def configure(self, obfuscated_key: bytes, content_id: bytes):
        self._obfuscatedKey.write(obfuscated_key)
        self._contentId.write(content_id)

        runtime.emulate_call(
            self._mu,
            self._vm_object_transform,
            [
                self._vmObj.ptr(),
                self._obfuscatedKey.ptr(),
                self._derivedKey.ptr(),
                self._contentId.ptr(),
            ],
        )
        logger.debug("Derived key: %s", self._derivedKey.read().hex())

        runtime.emulate_call(
            self._mu,
            self._initWithKey,
            [self._state.ptr(), self._derivedKey.ptr(), self._out_word.ptr()],
        )

    def generate_keystream(self) -> bytearray:
        runtime.emulate_call(
            self._mu,
            self._generateKeystream,
            [self._state.ptr(), self._keyStream.ptr()],
        )
        return self._keyStream.read()
