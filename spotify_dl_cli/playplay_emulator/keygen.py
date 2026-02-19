from pathlib import Path
from typing import Callable, Iterable
import pefile
from spotify_dl_cli.playplay_emulator.constants import ADDR, SIZES
from spotify_dl_cli.playplay_emulator.emulator import KeyEmu

"""
PlayPlayKeygen provides a high-level interface for key derivation and
PlayPlay decryption by relying on emulation of the original PE binary.
"""


class PlayPlayKeygen:
    def __init__(self, pe_path: Path):
        self._pe = pefile.PE(pe_path)
        self._emu = KeyEmu(self._pe)

        self._playplay_token = self._read_playplay_token()

        self._content_id: bytes | None = None
        self._obfuscated_key: bytes | None = None
        self._derived_key: bytes | None = None

    def configure(self, file_id: bytes, obfuscated_key: bytes) -> None:
        self._content_id = file_id[:16]
        self._obfuscated_key = obfuscated_key

        self._derived_key = self._emu.getDerivedKey(
            obfuscated_key, self._content_id, trace_file=None
        )

    def _read_playplay_token(self) -> bytes:
        image_base = self._pe.OPTIONAL_HEADER.ImageBase  # type: ignore
        rva = ADDR.PLAYPLAY_TOKEN - image_base
        data = self._pe.get_data(rva, SIZES.PLAYPLAY_TOKEN)

        if len(data) != SIZES.PLAYPLAY_TOKEN:
            raise ValueError("Invalid PlayPlay token size")

        return data

    def generate_keystream(self, state: bytearray):
        if self._derived_key is None:
            raise RuntimeError("Keygen not configured")

        keystream = self._emu.generateKeystream(state=state, trace_file=None)

        return keystream

    def decrypt_block(
        self,
        source: Callable[[], Iterable[bytearray]],
        sink: Callable[[bytearray], int | None],
    ) -> None:
        if self._derived_key is None:
            raise RuntimeError("Keygen not configured")

        _, initial_state = self._emu.obfuscatedInitializeWithKey(
            self._derived_key, trace_file=None
        )

        for buf in source():
            self._emu.decryptBufferInPlace(
                buf=buf, state=initial_state, trace_file=None
            )
            sink(buf)

    def decrypt_stream(self, source: Iterable[bytearray]) -> Iterable[bytearray]:
        if self._derived_key is None:
            raise RuntimeError("Keygen not configured")

        _, initial_state = self._emu.obfuscatedInitializeWithKey(
            self._derived_key, trace_file=None
        )

        for buf in source:
            self._emu.decryptBufferInPlace(
                buf=buf, state=initial_state, trace_file=None
            )
            yield buf

    @property
    def derived_key(self) -> bytes:
        if self._derived_key is None:
            raise RuntimeError("Keygen not configured")
        return self._derived_key

    @property
    def playplay_token(self) -> bytes:
        return self._playplay_token
