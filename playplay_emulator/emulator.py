import struct
import pefile
from typing import Optional, TextIO
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn.unicorn import Uc
from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EAX
import patch_binary
from playplay_emulator.playplay_ctx import PlayPlayCtx
from call_trace import CallTrace
from . import key_derivation_vm


EXE_PATH = "bin.exe"

ADDR_DERIVE_KEY = 0x0082745A
ADDR_INIT_WITH_KEY = 0x006FA93C
ADDR_GEN_KEYSTREAM = 0x006F9AEC
ADDR_SEEK_STATE_BLOCK = 0x006FAC49

MAGIC_RET = 0xDEADBEEF

STACK_ADDR = 0x00100000
STACK_SIZE = 0x00100000

HEAP_ADDR = 0x00200000
HEAP_SIZE = 0x00200000

FUNCTIONS_TO_STUB = [
    0x004EC2C8,
    0x00EB7AE1,
    0x00EB9096,
    0x00EB917D,
    0x00463D85,
    0x00ECC5C7,
]

DERIVED_KEY_SIZE = 24
KEYSTREAM_SIZE = 16
OFUSCATED_KEY_SIZE = 16
CONTENT_ID_SIZE = 16

ENABLE_INSTR_LOG = True


class KeyEmu:
    def __init__(self, pe: pefile.PE) -> None:
        self.pe = pe
        self.unicorn = Uc(UC_ARCH_X86, UC_MODE_32)

        self.disasm = Cs(CS_ARCH_X86, CS_MODE_32)

        self.image_base = pe.OPTIONAL_HEADER.ImageBase  # type: ignore

        self.shadow_callstack: Optional[CallTrace] = None
        self._callstack_hook_handle: Optional[int] = None

        self._initialized = False
        self._setup()

    def _setup(self) -> None:
        if self._initialized:
            return

        self.unicorn.mem_map(STACK_ADDR, STACK_SIZE)
        self.unicorn.mem_map(HEAP_ADDR, HEAP_SIZE)

        self._load_pe_image()

        patch_binary.install_stubs(self.unicorn, FUNCTIONS_TO_STUB)

        if self.shadow_callstack and self._callstack_hook_handle is None:
            self._callstack_hook_handle = self.unicorn.hook_add(
                UC_HOOK_CODE,
                self.shadow_callstack.hook,
            )

        playplay_key_pool_ptr = HEAP_ADDR + 0x1000

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

    def _init_stack(self) -> int:
        esp = STACK_ADDR + STACK_SIZE - 0x2000
        self.unicorn.reg_write(UC_X86_REG_ESP, esp)
        self.unicorn.reg_write(UC_X86_REG_EBP, esp)
        return esp

    def _emu_with_calltrace(
        self,
        start_addr: int,
        trace_file: TextIO | None,
    ) -> Optional[CallTrace]:
        shadow = None
        hook_handle = None

        if trace_file is not None:
            shadow = CallTrace(
                disassembler=self.disasm,
                trace_file=trace_file,
                enable_instr_log=ENABLE_INSTR_LOG,
            )
            hook_handle = self.unicorn.hook_add(
                UC_HOOK_CODE,
                shadow.hook,
            )

        try:
            self.unicorn.emu_start(start_addr, MAGIC_RET)
        finally:
            if hook_handle is not None:
                self.unicorn.hook_del(hook_handle)

        return shadow

    def _read_u32(self, addr: int) -> int:
        return struct.unpack("<I", self.unicorn.mem_read(addr, 4))[0]

    def _pack_u32(self, value: int) -> bytes:
        return struct.pack("<I", value)

    def _write_u32(self, addr: int, value: int) -> None:
        self.unicorn.mem_write(addr, self._pack_u32(value))

    def _write_stack_args(self, esp: int, *u32_values: int) -> None:
        for i, v in enumerate(u32_values):
            self._write_u32(esp + 4 * i, v)

    def getDerivedKey(
        self,
        obfuscated_key: bytes,
        content_id: bytes,
        trace_file: TextIO | None = None,
    ) -> bytes:
        assert len(obfuscated_key) == OFUSCATED_KEY_SIZE
        assert len(content_id) == CONTENT_ID_SIZE

        esp = self._init_stack()

        obfuscated_key_addr = HEAP_ADDR + 0x100
        derived_key_addr = HEAP_ADDR + 0x200
        content_id_addr = HEAP_ADDR + 0x300

        self.unicorn.mem_write(obfuscated_key_addr, obfuscated_key)
        self.unicorn.mem_write(content_id_addr, content_id)

        self._write_stack_args(
            esp,
            MAGIC_RET,
            obfuscated_key_addr,
            derived_key_addr,
            content_id_addr,
        )

        self._emu_with_calltrace(ADDR_DERIVE_KEY, trace_file)
        return bytes(self.unicorn.mem_read(derived_key_addr, DERIVED_KEY_SIZE))

    def initializeWithKey(
        self,
        derived_key: bytes,
        trace_file: TextIO | None = None,
    ) -> tuple[bytes, int]:
        assert len(derived_key) == DERIVED_KEY_SIZE

        esp = self._init_stack()

        state_addr = HEAP_ADDR + 0x4000  # 744 bytes
        setup_value_addr = HEAP_ADDR + 0x4500  # 4 bytes
        derived_key_addr = HEAP_ADDR + 0x4600  # 24 bytes

        self.unicorn.mem_write(state_addr, b"\x00" * PlayPlayCtx.field_size("state"))
        self.unicorn.mem_write(
            setup_value_addr, b"\x00" * PlayPlayCtx.field_size("setup_value")
        )
        self.unicorn.mem_write(derived_key_addr, derived_key)

        self._write_stack_args(
            esp,
            MAGIC_RET,
            state_addr,
            derived_key_addr,
            setup_value_addr,
        )

        self._emu_with_calltrace(ADDR_INIT_WITH_KEY, trace_file)

        state = bytes(
            self.unicorn.mem_read(state_addr, PlayPlayCtx.field_size("state"))
        )
        setup_value = self._read_u32(setup_value_addr)

        return state, setup_value

    def generateKeystream(
        self,
        state: bytes,
        trace_file: TextIO | None = None,
    ) -> tuple[bytes, bytes]:
        assert len(state) == PlayPlayCtx.field_size("state")

        esp = self._init_stack()

        state_addr = HEAP_ADDR + 0x4000
        keystream_addr = HEAP_ADDR + 0x5000

        self.unicorn.mem_write(state_addr, state)
        self.unicorn.mem_write(
            keystream_addr, b"\x00" * PlayPlayCtx.field_size("keystream")
        )

        self._write_stack_args(
            esp,
            MAGIC_RET,
            state_addr,
            keystream_addr,
        )

        self._emu_with_calltrace(ADDR_GEN_KEYSTREAM, trace_file)

        new_state = bytes(
            self.unicorn.mem_read(state_addr, PlayPlayCtx.field_size("state"))
        )
        keystream = bytes(
            self.unicorn.mem_read(keystream_addr, PlayPlayCtx.field_size("keystream"))
        )

        return new_state, keystream

    def seek_state_to_block(
        self,
        state: bytes,
        block_index: int,
        trace_file: TextIO | None = None,
    ) -> bytes:
        assert len(state) == PlayPlayCtx.field_size("state")
        assert struct.pack("<I", block_index)

        esp = self._init_stack()

        state_addr = HEAP_ADDR + 0x4000
        self.unicorn.mem_write(state_addr, state)

        self._write_stack_args(
            esp,
            MAGIC_RET,
            state_addr,
            block_index,
        )

        self._emu_with_calltrace(ADDR_SEEK_STATE_BLOCK, trace_file)

        return bytes(
            self.unicorn.mem_read(state_addr, PlayPlayCtx.field_size("state"))
        )
