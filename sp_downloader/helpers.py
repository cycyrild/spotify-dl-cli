from ogg_parser import reconstruct_ogg_from_chunks
from typing import Iterator
from playplay_emulator.keygen import PlayPlayKeygen
from http_client.http_client import HttpClient
from clt_extended_metadata.extendedmetadata_pb2 import Track
from sp_downloader.constants import CHUNK_SIZE
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


def slugify(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^\w]+", "_", value)
    return value.strip("_")


def generate_output_filename(track: Track) -> str:

    track_name = slugify(track.name)
    album_name = slugify(track.album.name) if track.album else "unknown_album"
    artist = track.artist[0].name if track.artist else "unknown_artist"
    artist_name = slugify(artist)

    return f"{track_name}_{album_name}_{artist_name}.ogg"
