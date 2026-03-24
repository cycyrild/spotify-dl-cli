from enum import Enum, auto
from typing import Final, cast

from spotify_dl_cli.clt_extended_metadata.extendedmetadata_pb2 import AudioFile


class Codec(Enum):
    VORBIS = auto()
    FLAC = auto()


VORBIS_FORMATS: Final[set[AudioFile.Format]] = {
    AudioFile.OGG_VORBIS_96,
    AudioFile.OGG_VORBIS_160,
    AudioFile.OGG_VORBIS_320,
}

FLAC_FORMATS: Final[set[AudioFile.Format]] = {
    AudioFile.FLAC_FLAC,
    AudioFile.FLAC_FLAC_24BIT,
    AudioFile.MP4_FLAC,
    AudioFile.MP4_FLAC_24BIT,
}


FORMAT_TO_CODEC: dict[AudioFile.Format, Codec] = {
    **{fmt: Codec.VORBIS for fmt in VORBIS_FORMATS},
    **{fmt: Codec.FLAC for fmt in FLAC_FORMATS},
}

SUPPORTED_FORMATS = FORMAT_TO_CODEC.keys()

EXTENSION_BY_CODEC: dict[Codec, str] = {Codec.VORBIS: "ogg", Codec.FLAC: "flac"}


def audio_formats() -> tuple[dict[str, AudioFile.Format], dict[AudioFile.Format, str]]:
    cli_to_enum: dict[str, AudioFile.Format] = {}
    enum_to_cli: dict[AudioFile.Format, str] = {}

    for value in AudioFile.Format.values():
        fmt = cast(AudioFile.Format, value)

        if fmt not in SUPPORTED_FORMATS:
            continue

        name = AudioFile.Format.Name(fmt)
        key = name.lower().replace("_", "-")

        cli_to_enum[key] = fmt
        enum_to_cli[fmt] = key

    return cli_to_enum, enum_to_cli


_AUDIO_FORMATS, _AUDIO_FORMATS_REVERSE = audio_formats()

CLI_FORMATS = tuple(_AUDIO_FORMATS)


def cli_to_format(value: str) -> AudioFile.Format:
    return _AUDIO_FORMATS[value]


def format_to_cli(value: AudioFile.Format) -> str | None:
    return _AUDIO_FORMATS_REVERSE.get(value)


def format_to_codec(fmt: AudioFile.Format) -> Codec:
    return FORMAT_TO_CODEC[fmt]


def format_to_extension(fmt: AudioFile.Format) -> str:
    return EXTENSION_BY_CODEC[format_to_codec(fmt)]
