import base64
from pathlib import Path
from mutagen.oggvorbis import OggVorbis
from mutagen.flac import Picture
from spotify_dl_cli.clt_extended_metadata.extendedmetadata_pb2 import Track
from spotify_dl_cli.http_client.http_client import HttpClient


def _set_tag(tags: dict[str, list[str]], key: str, value) -> None:
    if value is None:
        return

    if isinstance(value, (list, tuple, set)):
        values = [str(v) for v in value if v is not None]
        if values:
            tags[key] = values
        return

    tags[key] = [str(value)]


def _add_tag(tags: dict[str, list[str]], key: str, value) -> None:
    if value is None:
        return

    if key not in tags:
        tags[key] = []

    tags[key].append(str(value))


def _format_album_date(track: Track) -> str | None:
    if not track.album or not track.album.date or not track.album.date.year:
        return None

    year = track.album.date.year
    month = getattr(track.album.date, "month", 0)
    day = getattr(track.album.date, "day", 0)

    if month and day:
        return f"{year:04d}-{month:02d}-{day:02d}"

    if month:
        return f"{year:04d}-{month:02d}"

    return str(year)


def _download_largest_cover(track: Track, http_client: HttpClient) -> bytes | None:
    if not track.album or not track.album.cover_group:
        return None

    images = track.album.cover_group.image
    if not images:
        return None

    largest = max(images, key=lambda img: img.width or 0)

    resp = http_client.get(f"https://i.scdn.co/image/{largest.file_id.hex()}")
    resp.raise_for_status()

    return resp.content


def build_tags(track: Track) -> dict[str, list[str]]:
    tags: dict[str, list[str]] = {}

    _set_tag(tags, "TITLE", track.name)

    if track.original_title and track.original_title != track.name:
        _set_tag(tags, "ORIGINALTITLE", track.original_title)

    _set_tag(tags, "TRACKNUMBER", track.number)
    _set_tag(tags, "DISCNUMBER", track.disc_number)

    if track.version_title:
        _set_tag(tags, "VERSION", track.version_title)

    if track.artist:
        _set_tag(
            tags, "ARTIST", [artist.name for artist in track.artist if artist.name]
        )

    for ext in track.external_id:
        ext_type = ext.type.lower()
        if ext_type == "isrc":
            _set_tag(tags, "ISRC", ext.id)
        elif ext_type in ("upc", "ean"):
            _set_tag(tags, "BARCODE", ext.id)
        else:
            _add_tag(tags, f"SPOTIFY_{ext.type.upper()}", ext.id)

    if track.explicit:
        _set_tag(tags, "CONTENTRATING", "Explicit")

    if track.content_rating:
        for rating in track.content_rating:
            for tag in rating.tag:
                _add_tag(tags, "CONTENTRATING", tag)

    if track.language_of_performance:
        _set_tag(tags, "LANGUAGE", track.language_of_performance)

    if track.album:
        _set_tag(tags, "ALBUM", track.album.name)

        if track.album.artist:
            _set_tag(
                tags,
                "ALBUMARTIST",
                [artist.name for artist in track.album.artist if artist.name],
            )

        if track.album.label:
            _set_tag(tags, "ORGANIZATION", track.album.label)

        if track.album.genre:
            _set_tag(tags, "GENRE", track.album.genre)

        _set_tag(tags, "DATE", _format_album_date(track))

        if track.album.copyright:
            for copyright_ in track.album.copyright:
                _add_tag(tags, "COPYRIGHT", copyright_.text)

    if track.canonical_uri:
        _set_tag(tags, "SPOTIFY_URI", track.canonical_uri)

    if track.popularity is not None:
        _set_tag(tags, "SPOTIFY_POPULARITY", track.popularity)

    return tags


def apply_metadata(output_path: Path, track: Track, http_client: HttpClient) -> None:
    audio = OggVorbis(output_path)
    audio.clear()

    for key, values in build_tags(track).items():
        audio[key] = values

    cover_bytes = _download_largest_cover(track, http_client)
    if cover_bytes:
        picture = Picture()
        picture.type = 3
        picture.mime = "image/jpeg"
        picture.desc = "Cover"
        picture.data = cover_bytes

        encoded = base64.b64encode(picture.write()).decode("ascii")
        audio["metadata_block_picture"] = [encoded]

    audio.save()
