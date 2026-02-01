import logging
from typing import Iterator

from http_client import HttpClient
from metadata_helpers import ExtendedMetadataClient
from ogg_parser import reconstruct_ogg_from_chunks
from playplay_client import PlayPlayClient
from playplay_emulator.playplay_keygen import PlayPlayKeygen
from proto.track_pb2 import AudioFile, Track
from storage_resolve_helpers import StorageResolver


TARGET_AUDIO_FORMAT = AudioFile.Format.OGG_VORBIS_160
CHUNK_SIZE = 0x10000

logger = logging.getLogger(__name__)


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


def download_track_160kbps(
    http_client: HttpClient,
    track: Track,
    resolver: StorageResolver,
    playplay: PlayPlayClient,
    keygen: PlayPlayKeygen,
) -> None:
    file_id = next(
        (audio.file_id for audio in track.file if audio.format == TARGET_AUDIO_FORMAT),
        None,
    )

    if not file_id:
        logger.warning("OGG 160 kbps not available")
        return

    logger.info("Selected file_id: %s", file_id.hex())

    obfuscated_key = playplay.get_obfuscated_key(file_id)
    logger.debug("Obfuscated key: %s", obfuscated_key.hex())

    keygen.configure(file_id=file_id, obfuscated_key=obfuscated_key)
    logger.debug("Derived key: %s", keygen.derived_key.hex())

    urls = resolver.resolve(file_id)
    if not urls:
        raise RuntimeError("No URLs returned from storage resolver")

    output_path = f"{file_id.hex()}.ogg"
    logger.info("Downloading from %s", urls[0])

    with open(output_path, "wb") as output_file:
        for ogg_page in download_decrypt_and_reconstruct(
            http_client,
            urls[0],
            keygen,
        ):
            output_file.write(ogg_page)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    BEARER = "BQBBDVjhefX4kz9ql-6P3o_J5PTgA5HzKlFdaEAMh8zJdiOMxzP04RrCFHpr2KZVaA-a9oFxziXoYxlaDyFx1pqjY3s9ghRSff1tN1iBPhh9o1YBfQ4RRHIKk1lhnkvAcpAqjEsrlUNZOPlPXbOA4UoLespjfZ0SDWdz7jlDBtcItn1JzVFuf3Ulj4rAvh_dffvQvF2pCwTJi3YT3h9dEZEIcc08KZ5xPBDWcSwFIq_Zp94LosvmHT48Wsj9r756YZXIY_Qu4jbmvmiYzOPmp-6rmfHXzGMwlakuXO_ekgbGlAuRFqlqL-z7Xv8e7NXteq86Hh46-Q2HPTNJPsxWM4K9Xiw3CXOdSz89zJHANDxAwcAvgIq93zE1tuUSwHyKvgvAVh5MOOkWme2CGTkFpUY"
    EXE_PATH = "bin.exe"

    TRACK_URIS = [
        "spotify:track:7fLzbEOBOae9lUnOwr7Tse",
        "spotify:track:2P4OICZRVAQcYAV2JReRfj",
        "spotify:track:3CRDbSIZ4r5MsZ0YwxuEkn"
    ]

    client = HttpClient(BEARER)
    keygen = PlayPlayKeygen(EXE_PATH)

    metadata = ExtendedMetadataClient(client)
    resolver = StorageResolver(client)
    playplay = PlayPlayClient(client, keygen._playplay_token)

    tracks = metadata.fetch_tracks(TRACK_URIS)

    for uri, track in tracks.items():
        logger.info("Track URI: %s", uri)
        logger.info("Name: %s", track.name)
        logger.info("Duration: %s", track.duration)
        logger.info("GID: %s", track.gid.hex())

        download_track_160kbps(
            client,
            track,
            resolver,
            playplay,
            keygen,
        )


if __name__ == "__main__":
    main()
