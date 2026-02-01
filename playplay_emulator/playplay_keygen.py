import ctypes
import pefile
from playplay_emulator.constants import ADDR, SIZES
from playplay_emulator.emulator import KeyEmu
from playplay_emulator.playplay_ctx import PlayPlayCtx


class PlayPlayKeygen:
    def __init__(self, pe_path: str):
        self._pe = pefile.PE(pe_path)
        self._emu = KeyEmu(self._pe)

        self._playplay_token = self._read_playplay_token()

        self._content_id: bytes | None = None
        self._obfuscated_key: bytes | None = None
        self._derived_key: bytes | None = None
        self._playplay_ctx: PlayPlayCtx | None = None

    def configure(self, content_id: bytes, obfuscated_key: bytes) -> None:
        self._content_id = content_id
        self._obfuscated_key = obfuscated_key

        self._playplay_ctx = PlayPlayCtx()

        self._derived_key = self._emu.getDerivedKey(
            obfuscated_key,
            content_id,
            trace_file=None,
        )

        setup_value, state = self._emu.obfuscatedInitializeWithKey(
            self._derived_key,
            trace_file=None,
        )

        ctypes.memmove(
            ctypes.addressof(self._playplay_ctx.state),
            state,
            len(state),
        )

        self._playplay_ctx.ready_flag = 1
        self._playplay_ctx.setup_value = setup_value

        keystream, updated_state = self._emu.generateKeystream(
            bytes(self._playplay_ctx.state),  # état courant
            trace_file=None,
        )

        ctypes.memmove(
            ctypes.addressof(self._playplay_ctx.keystream),
            keystream,
            len(keystream),
        )
        
        ctypes.memmove(
            ctypes.addressof(self._playplay_ctx.state),
            updated_state,
            len(updated_state),
        )
        
        self._playplay_ctx.initialized = 1
        self._playplay_ctx.block_index = 0

    def _read_playplay_token(self) -> bytes:
        image_base = self._pe.OPTIONAL_HEADER.ImageBase  # type: ignore
        rva = ADDR.PLAYPLAY_TOKEN - image_base
        data = self._pe.get_data(rva, SIZES.PLAYPLAY_TOKEN)

        if len(data) != SIZES.PLAYPLAY_TOKEN:
            raise ValueError("Invalid PlayPlay token size")

        return data

    def generate_keystream(self) -> bytes:
        if self._playplay_ctx is None:
            raise RuntimeError("Keygen not configured")

        keystream, state = self._emu.generateKeystream(
            bytes(self._playplay_ctx.state), # type: ignore
            trace_file=None,
        )
        ctypes.memmove(
            ctypes.addressof(self._playplay_ctx.state),
            state,
            len(state),
        )
        return keystream

    def seek_state_to_block(self, block_index: int) -> bytes:
        if self._playplay_ctx is None:
            raise RuntimeError("Keygen not configured")

        return self._emu.seekStateToBlock(
            bytes(self._playplay_ctx.state), # type: ignore
            block_index,
            trace_file=None,
        )
    
    def decrypt_block(self, data: bytearray) -> None:
        if self._playplay_ctx is None:
            raise RuntimeError("Keygen not configured")

        self._emu.decryptBufferInPlace(
            buf=data,
            initial_state=bytes(self._playplay_ctx.state),  # type: ignore
            initial_keystream=bytes(self._playplay_ctx.keystream),  # type: ignore
            trace_file=None,
        )

    @property
    def derived_key(self) -> bytes:
        if self._derived_key is None:
            raise RuntimeError("Keygen not configured")
        return self._derived_key

    @property
    def playplay_token(self) -> bytes:
        return self._playplay_token
