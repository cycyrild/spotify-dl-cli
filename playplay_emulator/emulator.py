import struct
import pefile
from typing import Optional, TextIO
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn.unicorn import Uc
from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_ECX

import patch_binary
from playplay_emulator.playplay_ctx import PlayPlayCtx
from call_trace import CallTrace
from . import key_derivation_vm


EXE_PATH = "bin.exe"

ADDR_DERIVE_KEY = 0x0082745A
ADDR_PLAYPLAY_INIT_WITH_KEY = 0x006F9A92

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

    def getDerivedKey(
        self,
        obfuscated_key: bytes,
        content_id: bytes,
        trace_file: TextIO | None = None,
    ) -> bytes:
        assert len(obfuscated_key) == 16
        assert len(content_id) == 16

        esp = self._init_stack()

        obfuscated_key_addr = HEAP_ADDR + 0x100
        derived_key_addr = HEAP_ADDR + 0x200
        content_id_addr = HEAP_ADDR + 0x300

        self.unicorn.mem_write(obfuscated_key_addr, obfuscated_key)
        self.unicorn.mem_write(content_id_addr, content_id)

        self.unicorn.mem_write(esp, struct.pack("<I", MAGIC_RET))
        self.unicorn.mem_write(esp + 4, struct.pack("<I", obfuscated_key_addr))
        self.unicorn.mem_write(esp + 8, struct.pack("<I", derived_key_addr))
        self.unicorn.mem_write(esp + 12, struct.pack("<I", content_id_addr))

        shadow = self._emu_with_calltrace(
            ADDR_DERIVE_KEY,
            trace_file,
        )

        return bytes(self.unicorn.mem_read(derived_key_addr, 24))

    def playplayInitializeWithKey(
        self,
        derived_key: bytes,
        trace_file: TextIO | None = None,
    ) -> PlayPlayCtx:
        assert len(derived_key) == 24

        esp = self._init_stack()

        ctx_addr = HEAP_ADDR + 0x2000
        derived_key_addr = HEAP_ADDR + 0x3000

        self.unicorn.mem_write(ctx_addr, b"\x00" * PlayPlayCtx.size())
        self.unicorn.mem_write(derived_key_addr, derived_key)

        self.unicorn.mem_write(esp, struct.pack("<I", MAGIC_RET))
        self.unicorn.mem_write(esp + 4, struct.pack("<I", derived_key_addr))

        self.unicorn.reg_write(UC_X86_REG_ECX, ctx_addr)

        shadow = self._emu_with_calltrace(
            ADDR_PLAYPLAY_INIT_WITH_KEY,
            trace_file,
        )

        ctx_bytes = bytes(self.unicorn.mem_read(ctx_addr, PlayPlayCtx.size()))
        return PlayPlayCtx.from_bytes(ctx_bytes)
