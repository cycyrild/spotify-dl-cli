import pefile
from typing import Optional, TextIO
from unicorn.unicorn import Uc
from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    UC_HOOK_MEM_FETCH,
    UC_MODE_32,
)
from . import patch_binary
from .helpers import pack_u32
from .playplay_ctx import PlayPlayCtx
from .trace import InstructionTrace
from . import key_derivation_vm
from .unicorn_utils import UnicornStackUtils
from .constants import *
import numpy as np


class KeyEmu:
    def __init__(self, pe: pefile.PE) -> None:
        self.pe = pe
        self.image_base = pe.OPTIONAL_HEADER.ImageBase  # type: ignore
        self._image, self._image_size = self._prepare_pe_image()
        patch_binary.install_stubs_in_image(
            self._image, self.image_base, FUNCTIONS_TO_STUB
        )
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

        stack_utils = UnicornStackUtils(uc, STACK.ADDR, STACK.SIZE)
        return uc, stack_utils

    def _emu_with_trace(
        self, uc: Uc, start_addr: int, trace_file: TextIO | None, until: int = MAGIC_RET
    ) -> Optional[InstructionTrace]:
        shadow: Optional[InstructionTrace] = None
        hook_code = None
        hook_mem = None

        if trace_file is not None:
            shadow = InstructionTrace(trace_file)

            hook_code = uc.hook_add(UC_HOOK_CODE, shadow.hook_code)
            hook_mem = uc.hook_add(
                UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE | UC_HOOK_MEM_FETCH,
                shadow.hook_mem,
            )
        try:
            uc.emu_start(begin=start_addr, until=until)
        finally:
            if hook_code is not None:
                uc.hook_del(hook_code)
            if hook_mem is not None:
                uc.hook_del(hook_mem)

        return shadow

    def getDerivedKey(
        self,
        obfuscated_key: bytes,
        content_id: bytes,
        trace_file: TextIO | None,
    ) -> bytes:
        assert len(obfuscated_key) == SIZES.OBFUSCATED_KEY
        assert len(content_id) == SIZES.CONTENT_ID

        uc, stack_utils = self._create_uc()
        esp = stack_utils.init_stack()

        playplay_key_pool_ptr = self._heap_ptr(HEAP.OFF_VM_WORKSPACE)
        key_derivation_vm.init_playplay_vm_workspace(uc, self.pe, playplay_key_pool_ptr)

        obfuscated_key_addr = self._heap_ptr(HEAP.OFF_OBFUSCATED_KEY)
        derived_key_addr = self._heap_ptr(HEAP.OFF_DERIVED_KEY)
        content_id_addr = self._heap_ptr(HEAP.OFF_CONTENT_ID)

        uc.mem_write(obfuscated_key_addr, obfuscated_key)
        uc.mem_write(content_id_addr, content_id)

        stack_utils.write_stack_args(
            esp,
            MAGIC_RET,
            obfuscated_key_addr,
            derived_key_addr,
            content_id_addr,
        )

        self._emu_with_trace(uc, ADDR.DERIVE_KEY, trace_file)
        return bytes(uc.mem_read(derived_key_addr, SIZES.DERIVED_KEY))

    def obfuscatedInitializeWithKey(
        self,
        derived_key: bytes,
        trace_file: TextIO | None,
    ) -> tuple[int, bytearray]:
        assert len(derived_key) == SIZES.DERIVED_KEY

        uc, stack_utils = self._create_uc()
        esp = stack_utils.init_stack()

        state_addr = self._heap_ptr(HEAP.OFF_STATE)
        setup_value_addr = self._heap_ptr(HEAP.OFF_SETUP_VALUE)
        derived_key_addr = self._heap_ptr(HEAP.OFF_DERIVED_KEY_IN)

        uc.mem_write(derived_key_addr, derived_key)

        stack_utils.write_stack_args(
            esp,
            MAGIC_RET,
            state_addr,
            derived_key_addr,
            setup_value_addr,
        )

        self._emu_with_trace(uc, ADDR.INIT_WITH_KEY, trace_file)

        state = bytearray(uc.mem_read(state_addr, PlayPlayCtx.field_size("state")))

        return stack_utils.read_u32(setup_value_addr), state

    def generateKeystream(
        self,
        state: bytearray,
        trace_file: TextIO | None,
    ) -> bytes:
        assert len(state) == PlayPlayCtx.field_size("state")

        uc, stack_utils = self._create_uc()
        esp = stack_utils.init_stack()

        state_addr = self._heap_ptr(HEAP.OFF_STATE)
        keystream_addr = self._heap_ptr(HEAP.OFF_KEYSTREAM)

        uc.mem_write(state_addr, bytes(state))

        stack_utils.write_stack_args(
            esp,
            MAGIC_RET,
            state_addr,
            keystream_addr,
        )

        self._emu_with_trace(uc, ADDR.GEN_KEYSTREAM, trace_file)

        keystream = uc.mem_read(
            keystream_addr,
            PlayPlayCtx.field_size("keystream"),
        )

        new_state = uc.mem_read(
            state_addr,
            PlayPlayCtx.field_size("state"),
        )
        state[:] = new_state

        return bytes(keystream)

    def seekStateToBlock(
        self,
        state: bytearray,
        block_index: int,
        trace_file: TextIO | None,
    ) -> None:
        assert len(state) == PlayPlayCtx.field_size("state")
        assert pack_u32(block_index)

        uc, stack_utils = self._create_uc()
        esp = stack_utils.init_stack()

        state_addr = self._heap_ptr(HEAP.OFF_STATE)

        uc.mem_write(state_addr, bytes(state))

        stack_utils.write_stack_args(
            esp,
            MAGIC_RET,
            state_addr,
            block_index,
        )

        self._emu_with_trace(uc, ADDR.SEEK_STATE_BLOCK, trace_file)

        new_state = uc.mem_read(
            state_addr,
            PlayPlayCtx.field_size("state"),
        )
        state[:] = new_state

    def decryptBufferInPlace(
        self,
        buf: bytearray,
        state: bytearray,
        trace_file: TextIO | None = None,
    ) -> None:
        assert len(state) == PlayPlayCtx.field_size("state")

        uc, stack_utils = self._create_uc()
        esp = stack_utils.init_stack()

        state_addr = self._heap_ptr(HEAP.OFF_STATE)
        ks_addr = self._heap_ptr(HEAP.OFF_KEYSTREAM)

        uc.mem_write(state_addr, bytes(state))

        buf_np = np.frombuffer(buf, dtype=np.uint8)
        size = buf_np.size
        offset = 0

        while offset < size:
            esp = stack_utils.init_stack()
            stack_utils.write_stack_args(
                esp,
                MAGIC_RET,
                state_addr,
                ks_addr,
            )

            self._emu_with_trace(uc, ADDR.GEN_KEYSTREAM, trace_file)

            ks = uc.mem_read(ks_addr, SIZES.KEYSTREAM)
            block_len = min(SIZES.KEYSTREAM, size - offset)

            buf_np[offset : offset + block_len] ^= np.frombuffer(
                ks, dtype=np.uint8, count=block_len
            )

            offset += block_len

        new_state = uc.mem_read(state_addr, len(state))
        state[:] = new_state
