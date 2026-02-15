import argparse
import logging
from audio_formats import AUDIO_FORMATS


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    log_level_choices = tuple(
        name
        for name, value in logging._nameToLevel.items()
        if isinstance(value, int) and name != "NOTSET"
    )

    parser.add_argument(
        "--tracks",
        nargs="+",
        help="List of Spotify track URIs (e.g. spotify:track:...)",
    )

    parser.add_argument(
        "--playlists",
        nargs="+",
        help="List of Spotify playlist URIs (e.g. spotify:playlist:...)",
    )

    parser.add_argument(
        "--quality", choices=sorted(AUDIO_FORMATS.keys()), default="ogg-vorbis-160"
    )

    parser.add_argument(
        "--exe-path", default=None, help="Path to a custom sp_client executable."
    )

    parser.add_argument(
        "--tokens-file",
        default=None,
        help=(
            "Path to the Spotify tokens JSON file. "
            "Default: user config directory (cwd-agnostic)."
        ),
    )

    parser.add_argument("--output", default="music")

    parser.add_argument(
        "--log-level", default="INFO", choices=log_level_choices, help="Log level"
    )

    return parser.parse_args()
