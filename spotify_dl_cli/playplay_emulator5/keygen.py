from collections.abc import Iterator, Iterable
from spotify_dl_cli.playplay_emulator5.key_emu import KeyEmu
from spotify_dl_cli.playplay_emulator5.consts import EMULATOR_SIZES
from pathlib import Path


class PlayplayKeygen:
    def __init__(self, sp_client_path: Path):
        self._emu = KeyEmu(sp_client_path)

        self._playplay_token = bytes(self._emu.playplay_token)

        self._content_id: bytes | None = None
        self._obfuscated_key: bytes | None = None
        self._configured = False

    def configure(self, file_id: bytes, obfuscated_key: bytes) -> None:
        self._content_id = file_id[: EMULATOR_SIZES.CONTENT_ID]
        self._obfuscated_key = obfuscated_key
        self._emu.configure(obfuscated_key, self._content_id)
        self._configured = True

    def decrypt_stream(self, source: Iterable[bytearray]) -> Iterator[bytearray]:
        if not self._configured:
            raise RuntimeError("Keygen not configured")

        for buf in source:
            i = 0
            buf_len = len(buf)
            while i < buf_len:
                keystream = self._emu.generate_keystream()
                for j in range(min(EMULATOR_SIZES.KEY, buf_len - i)):
                    buf[i + j] ^= keystream[j]

                i += EMULATOR_SIZES.KEY

            yield buf

    @property
    def playplay_token(self) -> bytes:
        return self._playplay_token
