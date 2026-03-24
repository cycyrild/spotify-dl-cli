from typing import Iterator
from spotify_dl_cli.http_client.http_client import HttpClient
from spotify_dl_cli.sp_downloader.constants import CHUNK_SIZE
from spotify_dl_cli.playplay_emulator5.consts import AUDIO_AES
from Crypto.Cipher import AES
from Crypto.Util import Counter


def download_decrypt(http: HttpClient, url: str, aes_key: bytes) -> Iterator[bytes]:
    cipher = AES.new(
        key=aes_key,
        mode=AES.MODE_CTR,
        counter=Counter.new(AUDIO_AES.KEY_SIZE_BITS, initial_value=AUDIO_AES.IV),
    )

    with http.stream(url, headers={"Range": "bytes=0-"}) as resp:
        resp.raise_for_status()

        for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
            yield cipher.decrypt(chunk)
