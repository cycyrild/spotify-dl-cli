import argparse
import logging
import sys
from .audio_formats import AUDIO_FORMATS


def parse_args() -> argparse.Namespace:
    deprecated_flags = {"--tracks", "--playlists"}
    used = deprecated_flags.intersection(sys.argv)

    if used:
        flags = ", ".join(sorted(used))
        raise SystemExit(
            f"{flags} is no longer supported.\n"
            "Use URIs as positional arguments:\n"
            "  spotify-dl-cli spotify:track:... spotify:playlist:..."
        )

    parser = argparse.ArgumentParser()

    log_level_choices = tuple(
        name
        for name, value in logging._nameToLevel.items()
        if isinstance(value, int) and name != "NOTSET"
    )

    parser.add_argument("uris", nargs="+", help="Spotify URIs (track or playlist)")

    parser.add_argument(
        "--quality", choices=sorted(AUDIO_FORMATS.keys()), default="ogg-vorbis-160"
    )

    parser.add_argument("--output-dir", default="music")

    parser.add_argument(
        "--log-level", default="INFO", choices=log_level_choices, help="Log level"
    )

    parser.add_argument(
        "--filename-template",
        default="{track.name}_{track.album.name}_{track.artist[0].name}",
    )

    return parser.parse_args()
