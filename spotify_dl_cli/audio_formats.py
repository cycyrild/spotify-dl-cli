from typing import Dict
from spotify_dl_cli.clt_extended_metadata.extendedmetadata_pb2 import AudioFile


def audio_formats() -> Dict[str, AudioFile.Format]:
    formats = {}

    for name, value in AudioFile.Format.items():
        lower = name.lower()

        if not lower.startswith("ogg_vorbis_"):
            continue

        key = lower.replace("_", "-")
        formats[key] = value

    return formats


AUDIO_FORMATS = audio_formats()
