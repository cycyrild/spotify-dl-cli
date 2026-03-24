from typing import cast
from spotify_dl_cli.clt_extended_metadata.extendedmetadata_pb2 import AudioFile


def audio_formats() -> dict[str, AudioFile.Format]:
    formats: dict[str, AudioFile.Format] = {}

    for name, value in AudioFile.Format.items():
        lower = name.lower()

        if not lower.startswith("ogg_vorbis_"):
            continue

        key = lower.replace("_", "-")
        formats[key] = cast(AudioFile.Format, value)

    return formats


AUDIO_FORMATS = audio_formats()
