import pefile
from typing import Optional, TextIO
from unicorn.unicorn import Uc, UcError
from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_BLOCK,
    UC_HOOK_CODE,
    UC_HOOK_MEM_FETCH_PROT,
    UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    UC_HOOK_MEM_FETCH,
    UC_MODE_32,
)
import patch_binary
from playplay_emulator.helpers import pack_u32
from playplay_emulator.playplay_ctx import PlayPlayCtx
from .trace import InstructionTrace
from . import key_derivation_vm
from .unicorn_utils import UnicornStackUtils
from .constants import *
from unicorn.x86_const import UC_X86_REG_EIP


class KeyEmu:
    def __init__(self, pe: pefile.PE) -> None:
        self.pe = pe
        self.unicorn = Uc(UC_ARCH_X86, UC_MODE_32)

        self.image_base = pe.OPTIONAL_HEADER.ImageBase  # type: ignore

        self.stack_utils = UnicornStackUtils(
            self.unicorn,
            STACK_ADDR,
            STACK_SIZE,
        )

        self._initialized = False
        self._setup()

    def _heap_ptr(self, offset: int) -> int:
        return HEAP_ADDR + offset

    def _setup(self) -> None:
        if self._initialized:
            return

        self.unicorn.mem_map(STACK_ADDR, STACK_SIZE)
        self.unicorn.mem_map(HEAP_ADDR, HEAP_SIZE)

        self._load_pe_image()

        patch_binary.install_stubs(self.unicorn, FUNCTIONS_TO_STUB)

        playplay_key_pool_ptr = self._heap_ptr(HEAP_OFF_VM_WORKSPACE)

        key_derivation_vm.init_playplay_vm_workspace(
            self.unicorn, self.pe, playplay_key_pool_ptr
        )

        self._initialized = True

    def _load_pe_image(self) -> None:
        self.pe.full_load()

        image = self.pe.get_memory_mapped_image(ImageBase=self.image_base)
        size = (len(image) + 0xFFF) & ~0xFFF

        self.unicorn.mem_map(self.image_base, size)
        self.unicorn.mem_write(self.image_base, image)

    def _emu_with_trace(
        self, start_addr: int, trace_file: TextIO | None, until: int = MAGIC_RET
    ) -> Optional[InstructionTrace]:
        shadow: Optional[InstructionTrace] = None
        hook_code = None
        hook_mem = None
        hook_fetch = None
        hook_block = None

        if trace_file is not None:
            shadow = InstructionTrace(trace_file)

            hook_code = self.unicorn.hook_add(UC_HOOK_CODE, shadow.hook_code)
            hook_mem = self.unicorn.hook_add(
                UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE | UC_HOOK_MEM_FETCH,
                shadow.hook_mem,
            )
            hook_fetch = self.unicorn.hook_add(
                UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_FETCH_PROT,
                shadow.hook_mem_invalid,
            )
            hook_block = self.unicorn.hook_add(UC_HOOK_BLOCK, shadow.hook_block)

        try:
            self.unicorn.emu_start(begin=start_addr, until=until)
        finally:
            if hook_code is not None:
                self.unicorn.hook_del(hook_code)
            if hook_mem is not None:
                self.unicorn.hook_del(hook_mem)
            if hook_fetch is not None:
                self.unicorn.hook_del(hook_fetch)
            if hook_block is not None:
                self.unicorn.hook_del(hook_block)

        return shadow

    def getDerivedKey(
        self,
        obfuscated_key: bytes,
        content_id: bytes,
        trace_file: TextIO | None,
    ) -> bytes:
        assert len(obfuscated_key) == OFUSCATED_KEY_SIZE
        assert len(content_id) == CONTENT_ID_SIZE

        esp = self.stack_utils.init_stack()

        obfuscated_key_addr = self._heap_ptr(HEAP_OFF_OBFUSCATED_KEY)
        derived_key_addr = self._heap_ptr(HEAP_OFF_DERIVED_KEY)
        content_id_addr = self._heap_ptr(HEAP_OFF_CONTENT_ID)

        self.unicorn.mem_write(obfuscated_key_addr, obfuscated_key)
        self.unicorn.mem_write(content_id_addr, content_id)

        self.stack_utils.write_stack_args(
            esp,
            MAGIC_RET,
            obfuscated_key_addr,
            derived_key_addr,
            content_id_addr,
        )

        self._emu_with_trace(ADDR_DERIVE_KEY, trace_file)
        return bytes(self.unicorn.mem_read(derived_key_addr, DERIVED_KEY_SIZE))

    def initializeWithKey(
        self,
        derived_key: bytes,
        trace_file: TextIO | None,
    ) -> tuple[bytes, int]:
        assert len(derived_key) == DERIVED_KEY_SIZE

        esp = self.stack_utils.init_stack()

        state_addr = self._heap_ptr(HEAP_OFF_STATE)
        setup_value_addr = self._heap_ptr(HEAP_OFF_SETUP_VALUE)
        derived_key_addr = self._heap_ptr(HEAP_OFF_DERIVED_KEY_IN)

        self.unicorn.mem_write(derived_key_addr, derived_key)

        self.stack_utils.write_stack_args(
            esp,
            MAGIC_RET,
            state_addr,
            derived_key_addr,
            setup_value_addr,
        )

        self._emu_with_trace(ADDR_INIT_WITH_KEY, trace_file)

        state = bytes(
            self.unicorn.mem_read(state_addr, PlayPlayCtx.field_size("state"))
        )
        setup_value = self.stack_utils.read_u32(setup_value_addr)

        return state, setup_value

    def generateKeystream(
        self,
        state: bytes,
        trace_file: TextIO | None,
    ) -> tuple[bytes, bytes]:
        assert len(state) == PlayPlayCtx.field_size("state")

        esp = self.stack_utils.init_stack()

        state_addr = self._heap_ptr(HEAP_OFF_STATE)
        keystream_addr = self._heap_ptr(HEAP_OFF_KEYSTREAM)

        self.unicorn.mem_write(state_addr, state)

        self.stack_utils.write_stack_args(
            esp,
            MAGIC_RET,
            state_addr,
            keystream_addr,
        )

        self._emu_with_trace(ADDR_GEN_KEYSTREAM, trace_file)

        new_state = bytes(
            self.unicorn.mem_read(state_addr, PlayPlayCtx.field_size("state"))
        )
        keystream = bytes(
            self.unicorn.mem_read(keystream_addr, PlayPlayCtx.field_size("keystream"))
        )

        return new_state, keystream

    def seekStateToBlock(
        self,
        state: bytes,
        block_index: int,
        trace_file: TextIO | None,
    ) -> bytes:
        assert len(state) == PlayPlayCtx.field_size("state")
        assert pack_u32(block_index)

        esp = self.stack_utils.init_stack()

        state_addr = self._heap_ptr(HEAP_OFF_STATE)
        self.unicorn.mem_write(state_addr, state)

        self.stack_utils.write_stack_args(
            esp,
            MAGIC_RET,
            state_addr,
            block_index,
        )
        self._emu_with_trace(ADDR_SEEK_STATE_BLOCK, trace_file)

        return bytes(self.unicorn.mem_read(state_addr, PlayPlayCtx.field_size("state")))
