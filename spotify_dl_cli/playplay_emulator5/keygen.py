from pathlib import Path
from spotify_dl_cli.playplay_emulator5.key_emu import KeyEmu


class PlayPlayKeygen:
    def __init__(self, sp_client_path: Path):
        self._emu = KeyEmu(sp_client_path)

        self._playplay_token = self._emu.playplay_token

        self._content_id: bytes | None = None
        self._obfuscated_key: bytes | None = None
        self._configured = False

    def configure(self, file_id: bytes, obfuscated_key: bytes) -> None:
        self._content_id = file_id[:16]
        self._obfuscated_key = obfuscated_key
        self._emu.configure(obfuscated_key, self._content_id)
        self._configured = True

    def generate_keystream(self) -> bytearray:
        return self._emu.generate_keystream()

    def decrypt_stream(self, source):
        if not self._configured:
            raise RuntimeError("Keygen not configured")

        for buf in source:
            i = 0
            while i < len(buf):
                keystream = self.generate_keystream()
                for j in range(min(len(keystream), len(buf) - i)):
                    buf[i + j] ^= keystream[j]

                i += len(keystream)

            yield buf

    @property
    def playplay_token(self) -> bytes:
        return bytes(self._playplay_token)
