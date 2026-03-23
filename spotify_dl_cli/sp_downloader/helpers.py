from spotify_dl_cli.ogg_parser import reconstruct_ogg_from_chunks
from typing import Iterator
from spotify_dl_cli.http_client.http_client import HttpClient
from spotify_dl_cli.sp_downloader.constants import CHUNK_SIZE
from spotify_dl_cli.playplay_emulator5.consts import AUDIO_AESIV
from Crypto.Cipher import AES
from Crypto.Util import Counter


def download_decrypt_and_reconstruct(
    http: HttpClient, url: str, aes_key: bytes
) -> Iterator[bytes]:
    cipher = AES.new(
        aes_key, AES.MODE_CTR, counter=Counter.new(128, initial_value=AUDIO_AESIV)
    )

    with http.stream(url, headers={"Range": "bytes=0-"}) as resp:
        resp.raise_for_status()
        decrypted_chunks = (
            cipher.decrypt(chunk)
            for chunk in resp.iter_content(chunk_size=CHUNK_SIZE)
            if chunk
        )

        yield from reconstruct_ogg_from_chunks(decrypted_chunks)


def iter_audio_files(track):
    if hasattr(track, "file"):
        for f in track.file:
            yield f
    for alt in track.alternative:
        for f in alt.file:
            yield f
