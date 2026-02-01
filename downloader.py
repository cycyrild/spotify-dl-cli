import logging
from typing import Iterator, List
from http_client import HttpClient
from ogg_parser import reconstruct_ogg_from_chunks
from clients.playplay_client import PlayPlayClient
from playplay_emulator.playplay_keygen import PlayPlayKeygen
from proto.track_pb2 import AudioFile, Track
from clients.storage_resolve_client import StorageResolverClient

CHUNK_SIZE = 0x10000
logger = logging.getLogger(__name__)

AUDIO_FORMATS = {
    "ogg-160": AudioFile.Format.OGG_VORBIS_160,
    "ogg-96": AudioFile.Format.OGG_VORBIS_96,
    "ogg-320": AudioFile.Format.OGG_VORBIS_320,
}


def download_decrypt_and_reconstruct(
    http: HttpClient,
    url: str,
    keygen: PlayPlayKeygen,
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


def download_track(
    http_client: HttpClient,
    track: Track,
    resolver: StorageResolverClient,
    playplay: PlayPlayClient,
    keygen: PlayPlayKeygen,
    audio_format: AudioFile.Format,
) -> None:
    file_id = next(
        (audio.file_id for audio in track.file if audio.format == audio_format),
        None,
    )

    if not file_id:
        logger.warning("Audio format unavailable for this track")
        return

    obfuscated_key = playplay.get_obfuscated_key(file_id)
    keygen.configure(file_id=file_id, obfuscated_key=obfuscated_key)

    urls = resolver.resolve(file_id)
    if not urls:
        raise RuntimeError("No URL returned by the resolver")

    output_path = f"{file_id.hex()}.ogg"
    logger.info("Downloading: %s", output_path)

    with open(output_path, "wb") as f:
        for ogg_page in download_decrypt_and_reconstruct(
            http_client,
            urls[0],
            keygen,
        ):
            f.write(ogg_page)
