import argparse
import sys

from .audio_formats import CLI_FORMATS

LOG_LEVEL_CHOICES = ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG")


def parse_args() -> argparse.Namespace:
    deprecated_flags = {"--tracks", "--playlists"}
    used = deprecated_flags.intersection(sys.argv)

    if used:
        flags = ", ".join(sorted(used))
        raise SystemExit(
            f"{flags} is no longer supported.\nUse URIs as positional arguments:\n"
            "spotify-dl-cli spotify:track:... spotify:playlist:..."
        )

    parser = argparse.ArgumentParser()

    parser.add_argument("uris", nargs="+", help="Spotify URIs (track or playlist)")

    parser.add_argument("--quality", choices=CLI_FORMATS, default="ogg-vorbis-160")

    parser.add_argument("--output-dir", default="music")

    parser.add_argument("--log-level", default="INFO", choices=LOG_LEVEL_CHOICES, help="Log level")

    parser.add_argument(
        "--filename-template",
        default="{track.name}_{track.album.name}_{track.artist[0].name}",
    )

    return parser.parse_args()
