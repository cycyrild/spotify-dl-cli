import logging
import struct
from pathlib import Path
from pefile import PE
from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64
from unicorn.unicorn import Uc
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RBX
from spotify_dl_cli.playplay_emulator5.consts import (
    AES_KEY_HOOK,
    EMULATOR_SIZES,
    MEM,
    PATHS,
    PLAYPLAY_TOKEN,
    RT_DATA,
    RT_FUNCTIONS,
)
from spotify_dl_cli.playplay_emulator5.emu import runtime
from spotify_dl_cli.playplay_emulator5.emu.addressing import rebase, align
from spotify_dl_cli.playplay_emulator5.emu.heap_allocator import HeapAllocator
from spotify_dl_cli.playplay_emulator5.emu.hooks.hook_malloc import hook_malloc
from spotify_dl_cli.playplay_emulator5.emu.hooks.stub_patches import stub_patches
from spotify_dl_cli.playplay_emulator5.seh import seh_hook
from spotify_dl_cli.playplay_emulator5.emu_session import EmuSession
from spotify_dl_cli.playplay_emulator5.seh.state_builder import build_state

logger = logging.getLogger(__name__)


class KeyEmu:
    def __init__(self, sp_client_path: Path) -> None:
        self._pe = PE(sp_client_path, fast_load=True)
        self._mapped_image = self._pe.get_memory_mapped_image()

        self._image_base = getattr(self._pe.OPTIONAL_HEADER, "ImageBase")
        self._image_size = align(len(self._mapped_image))

        self._seh_state = build_state(
            image_base=self._image_base,
            runtime_functions_path=PATHS.RUNTIME_FUNCTIONS_JSON,
            throw_infos_path=PATHS.THROW_INFOS_JSON,
        )

        self._playplay_token: bytearray | None = None
        self._vm_obj_blob: bytearray | None = None

    def _create_session(self) -> EmuSession:
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        if not isinstance(self._mapped_image, bytes):
            raise

        mu.mem_map(self._image_base, self._image_size)
        mu.mem_write(self._image_base, self._mapped_image)

        logger.debug(
            "PE mapped at 0x%X with size 0x%X", self._image_base, self._image_size
        )

        seh_hook.install_seh_hook(mu, self._seh_state)

        heap = HeapAllocator.create(mu, MEM.HEAP_ADDR, MEM.HEAP_SIZE)

        stub_patches(mu, self._image_base)
        hook_malloc(mu, self._image_base, heap)

        runtime.setup_stack(mu)
        runtime.setup_teb(mu)

        vm_obj = heap.alloc(EMULATOR_SIZES.VM_OBJECT)

        session = EmuSession(
            mu=mu,
            image_base=self._image_base,
            image_size=self._image_size,
            heap=heap,
            vm_object_transform=rebase(
                self._image_base, RT_FUNCTIONS.VM_OBJECT_TRANSFORM_VA
            ),
            vm_runtime_init=rebase(self._image_base, RT_FUNCTIONS.VM_RUNTIME_INIT_VA),
            aes_key_va=rebase(self._image_base, AES_KEY_HOOK.TRIGGER_RIP),
            vm_obj=vm_obj,
            obfuscated_key=heap.alloc(EMULATOR_SIZES.OBFUSCATED_KEY),
            content_id=heap.alloc(EMULATOR_SIZES.CONTENT_ID),
            derived_key=heap.alloc(EMULATOR_SIZES.DERIVED_KEY),
            captured_aes_key=None,
        )

        mu.hook_add(
            UC_HOOK_CODE,
            self._hook,
            session,
            begin=session.aes_key_va,
            end=session.aes_key_va,
        )

        if self._vm_obj_blob is None:
            self._init_runtime(session)
            self._vm_obj_blob = session.vm_obj.read()
        else:
            vm_obj.write(bytes(self._vm_obj_blob))

        return session

    def _init_runtime(self, session: EmuSession) -> None:
        rt_context = session.heap.alloc(0x10)
        data = bytearray(rt_context.size)

        struct.pack_into(
            "<Q", data, 8, rebase(session.image_base, RT_DATA.RUNTIME_CONTEXT_VA)
        )
        rt_context.write(bytes(data))

        runtime.emulate_call(
            session.mu, session.vm_runtime_init, [session.vm_obj.ptr, rt_context.ptr, 1]
        )

    def _read_playplay_token(self) -> bytearray:
        session = self._create_session()
        addr = rebase(session.image_base, PLAYPLAY_TOKEN.VA)
        return session.mu.mem_read(addr, PLAYPLAY_TOKEN.SIZE)

    @property
    def playplay_token(self) -> bytearray:
        if self._playplay_token is None:
            self._playplay_token = self._read_playplay_token()
        return self._playplay_token

    @staticmethod
    def _hook(mu: Uc, address: int, size: int, session: EmuSession) -> None:
        rax = mu.reg_read(UC_X86_REG_RAX)
        rbx = mu.reg_read(UC_X86_REG_RBX)

        if rax == AES_KEY_HOOK.TRIGGER_RAX and rbx == AES_KEY_HOOK.TRIGGER_RBX:
            logger.debug("AES key hook triggered, capturing key")
            session.captured_aes_key = mu.mem_read(rbx, EMULATOR_SIZES.KEY)
            mu.emu_stop()

    def get_aes_key(self, obfuscated_key: bytes, content_id: bytes) -> bytearray:
        session = self._create_session()

        session.obfuscated_key.write(obfuscated_key)
        session.content_id.write(content_id)

        runtime.emulate_call(
            session.mu,
            session.vm_object_transform,
            [
                session.vm_obj.ptr,
                session.obfuscated_key.ptr,
                session.derived_key.ptr,
                session.content_id.ptr,
            ],
        )

        if session.captured_aes_key is None:
            raise RuntimeError("Failed to capture decrypted key")

        return session.captured_aes_key
