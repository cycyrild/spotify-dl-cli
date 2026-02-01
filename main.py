import argparse
import logging
from downloader import AUDIO_FORMATS, download_track, logger
from clients.playplay_client import PlayPlayClient
from http_client import HttpClient
from playplay_emulator.playplay_keygen import PlayPlayKeygen
from clients.metadata_client import ExtendedMetadataClient
from clients.storage_resolve_client import StorageResolverClient


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Spotify OGG downloader")

    parser.add_argument(
        "--token",
        required=True,
        help="Spotify bearer token",
    )

    parser.add_argument(
        "--tracks",
        nargs="+",
        required=True,
        help="List of Spotify URIs (e.g., spotify:track:...)",
    )

    parser.add_argument(
        "--quality",
        choices=AUDIO_FORMATS.keys(),
        default="ogg-160",
        help="Audio quality (default: ogg-160)",
    )

    parser.add_argument(
        "--exe-path",
        default="bin.exe",
        help="Path to the PlayPlay executable",
    )

    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)s: %(message)s",
    )

    audio_format = AUDIO_FORMATS[args.quality]

    client = HttpClient(args.token)
    keygen = PlayPlayKeygen(args.exe_path)

    metadata = ExtendedMetadataClient(client)
    resolver = StorageResolverClient(client)
    playplay = PlayPlayClient(client, keygen._playplay_token)

    tracks = metadata.fetch_tracks(args.tracks)

    for uri, track in tracks.items():
        logger.info("Track: %s", track.name)
        logger.info("Duration: %s", track.duration)
        logger.info("GID: %s", track.gid.hex())

        download_track(
            client,
            track,
            resolver,
            playplay,
            keygen,
            audio_format,
        )


if __name__ == "__main__":
    main()
