from spotify_dl_cli.ogg_parser import reconstruct_ogg_from_chunks
from typing import Iterator
from spotify_dl_cli.playplay_emulator.keygen import PlayPlayKeygen
from spotify_dl_cli.http_client.http_client import HttpClient
from spotify_dl_cli.clt_extended_metadata.extendedmetadata_pb2 import Track
from spotify_dl_cli.sp_downloader.constants import CHUNK_SIZE
import re


def download_decrypt_and_reconstruct(
    http: HttpClient, url: str, keygen: PlayPlayKeygen
) -> Iterator[bytes]:
    with http.stream(url, headers={"Range": "bytes=0-"}) as resp:
        resp.raise_for_status()

        decrypted_chunks = (
            buf
            for buf in keygen.decrypt_stream(
                bytearray(chunk)
                for chunk in resp.iter_content(chunk_size=CHUNK_SIZE)
                if chunk
            )
            if buf
        )

        yield from reconstruct_ogg_from_chunks(decrypted_chunks)


def iter_audio_files(track):
    if hasattr(track, "file"):
        for f in track.file:
            yield f
    for alt in track.alternative:
        for f in alt.file:
            yield f
