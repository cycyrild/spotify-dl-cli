import pefile
from typing import TextIO
from unicorn.unicorn import Uc
from unicorn import UC_ARCH_X86, UC_MODE_32
from . import patch_binary
from .helpers import pack_u32
from .ctx import PLAYPLAY_CTX
from . import key_derivation_vm
from .unicorn_utils import UnicornStackUtils
from .constants import *
from .emu_with_trace import emu_with_trace

"""
This class provides low-level decryption primitives for Spotify's Playplay DRM by emulating the original PE implementation.
"""

"""
Each high-level emulation routine instantiates its own Unicorn engine to ensure clean state and independent traces.
decryptBufferInPlace() intentionally reuses a single instance across iterations for performance.

This per-routine engine isolation is for testing/debugging only and must not be used in production/performance-critical cases.
"""


class KeyEmu:
    def __init__(self, pe: pefile.PE) -> None:
        self.pe = pe
        self.image_base = pe.OPTIONAL_HEADER.ImageBase  # type: ignore
        # image_base should be 0x00400000
        self._image, self._image_size = self._prepare_pe_image()
        patch_binary.install_patches(self._image, self.image_base)
        self._image_ro = self._image

    def _heap_ptr(self, offset: int) -> int:
        return HEAP.ADDR + offset

    def _prepare_pe_image(self) -> tuple[bytearray, int]:
        self.pe.full_load()
        image = self.pe.get_memory_mapped_image(ImageBase=self.image_base)
        size = (len(image) + 0xFFF) & ~0xFFF
        buf = bytearray(image)
        return buf, size

    def _create_uc(self) -> tuple[Uc, UnicornStackUtils]:
        uc = Uc(UC_ARCH_X86, UC_MODE_32)

        uc.mem_map(STACK.ADDR, STACK.SIZE)
        uc.mem_map(HEAP.ADDR, HEAP.SIZE)

        uc.mem_map(self.image_base, self._image_size)

        uc.mem_write(self.image_base, bytes(self._image_ro))

        stack_utils = UnicornStackUtils(
            uc, STACK.ADDR, STACK.SIZE, HEAP.ADDR, HEAP.SIZE
        )
        return uc, stack_utils

    def getDerivedKey(
        self, obfuscated_key: bytes, content_id: bytes, trace_file: TextIO | None
    ) -> bytes:
        assert len(obfuscated_key) == SIZES.OBFUSCATED_KEY
        assert len(content_id) == SIZES.CONTENT_ID

        uc, stack_utils = self._create_uc()
        esp = stack_utils.init_stack()

        playplay_key_pool_ptr = stack_utils.next_heap(
            key_derivation_vm.VM_WORKSPACE_POOL_SIZE
        )

        key_derivation_vm.init_playplay_vm_workspace(uc, self.pe, playplay_key_pool_ptr)

        obfuscated_key_addr = stack_utils.next_heap(SIZES.OBFUSCATED_KEY)
        derived_key_addr = stack_utils.next_heap(SIZES.DERIVED_KEY)
        content_id_addr = stack_utils.next_heap(SIZES.CONTENT_ID)

        uc.mem_write(obfuscated_key_addr, obfuscated_key)
        uc.mem_write(content_id_addr, content_id)

        stack_utils.write_stack_args(
            esp, MAGIC_RET, obfuscated_key_addr, derived_key_addr, content_id_addr
        )

        emu_with_trace(uc, ADDR.DERIVE_KEY, trace_file)

        return bytes(uc.mem_read(derived_key_addr, SIZES.DERIVED_KEY))

    def obfuscatedInitializeWithKey(
        self, derived_key: bytes, trace_file: TextIO | None
    ) -> tuple[int, bytearray]:
        assert len(derived_key) == SIZES.DERIVED_KEY

        uc, stack_utils = self._create_uc()
        esp = stack_utils.init_stack()

        state_addr = stack_utils.next_heap(PLAYPLAY_CTX.STATE_SIZE)
        setup_value_addr = stack_utils.next_heap(PLAYPLAY_CTX.SETUP_VALUE_SIZE)
        derived_key_addr = stack_utils.next_heap(SIZES.DERIVED_KEY)

        uc.mem_write(derived_key_addr, derived_key)

        stack_utils.write_stack_args(
            esp, MAGIC_RET, state_addr, derived_key_addr, setup_value_addr
        )

        emu_with_trace(uc, ADDR.INIT_WITH_KEY, trace_file)

        state = bytearray(uc.mem_read(state_addr, PLAYPLAY_CTX.STATE_SIZE))
        setup_value = stack_utils.read_u32(setup_value_addr)
        return setup_value, state

    def generateKeystream(self, state: bytearray, trace_file: TextIO | None) -> bytes:
        assert len(state) == PLAYPLAY_CTX.STATE_SIZE

        uc, stack_utils = self._create_uc()
        esp = stack_utils.init_stack()

        state_addr = stack_utils.next_heap(PLAYPLAY_CTX.STATE_SIZE)
        keystream_addr = stack_utils.next_heap(PLAYPLAY_CTX.KEYSTREAM_SIZE)

        uc.mem_write(state_addr, bytes(state))

        stack_utils.write_stack_args(esp, MAGIC_RET, state_addr, keystream_addr)

        emu_with_trace(uc, ADDR.GEN_KEYSTREAM, trace_file)

        keystream = uc.mem_read(keystream_addr, PLAYPLAY_CTX.KEYSTREAM_SIZE)
        state[:] = uc.mem_read(state_addr, PLAYPLAY_CTX.STATE_SIZE)

        return bytes(keystream)

    def seekStateToBlock(
        self, state: bytearray, block_index: int, trace_file: TextIO | None
    ) -> None:
        assert len(state) == PLAYPLAY_CTX.STATE_SIZE
        assert pack_u32(block_index)

        uc, stack_utils = self._create_uc()
        esp = stack_utils.init_stack()

        state_addr = stack_utils.next_heap(PLAYPLAY_CTX.STATE_SIZE)

        uc.mem_write(state_addr, bytes(state))

        stack_utils.write_stack_args(esp, MAGIC_RET, state_addr, block_index)

        emu_with_trace(uc, ADDR.SEEK_STATE_BLOCK, trace_file)

        state[:] = uc.mem_read(state_addr, PLAYPLAY_CTX.STATE_SIZE)

    """
    For performance reasons, this function reuses a single Unicorn emulation instance across multiple GEN_KEYSTREAM() invocations.
    """

    def decryptBufferInPlace(
        self, buf: bytearray, state: bytearray, trace_file: TextIO | None = None
    ) -> None:
        assert len(state) == PLAYPLAY_CTX.STATE_SIZE

        uc, stack_utils = self._create_uc()

        state_addr = stack_utils.next_heap(PLAYPLAY_CTX.STATE_SIZE)
        ks_addr = stack_utils.next_heap(SIZES.KEYSTREAM)

        uc.mem_write(state_addr, bytes(state))

        buf_view = memoryview(buf)
        size = len(buf)
        offset = 0

        while offset < size:
            esp = stack_utils.init_stack()
            stack_utils.write_stack_args(esp, MAGIC_RET, state_addr, ks_addr)

            emu_with_trace(uc, ADDR.GEN_KEYSTREAM, trace_file)

            block_len = min(SIZES.KEYSTREAM, size - offset)
            ks = uc.mem_read(ks_addr, block_len)

            block = buf_view[offset : offset + block_len]
            for i in range(block_len):
                block[i] ^= ks[i]

            offset += block_len

        state[:] = uc.mem_read(state_addr, PLAYPLAY_CTX.STATE_SIZE)
