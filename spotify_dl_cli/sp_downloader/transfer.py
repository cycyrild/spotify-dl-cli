from spotify_dl_cli.ogg_parser import reconstruct_ogg_from_chunks
from typing import Iterator
from spotify_dl_cli.http_client.http_client import HttpClient
from spotify_dl_cli.sp_downloader.constants import CHUNK_SIZE
from spotify_dl_cli.playplay_emulator5.consts import AUDIO_AES
from Crypto.Cipher import AES
from Crypto.Util import Counter


def download_decrypt_and_reconstruct(
    http: HttpClient, url: str, aes_key: bytes
) -> Iterator[bytes]:
    cipher = AES.new(
        aes_key,
        AES.MODE_CTR,
        counter=Counter.new(AUDIO_AES.KEY_SIZE_BITS, initial_value=AUDIO_AES.IV),
    )

    with http.stream(url, headers={"Range": "bytes=0-"}) as resp:
        resp.raise_for_status()
        decrypted_chunks = (
            cipher.decrypt(chunk)
            for chunk in resp.iter_content(chunk_size=CHUNK_SIZE)
            if chunk
        )

        yield from reconstruct_ogg_from_chunks(decrypted_chunks)
