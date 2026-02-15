import base64
from pathlib import Path
from mutagen.oggvorbis import OggVorbis
from mutagen.flac import Picture
from clt_extended_metadata.extendedmetadata_pb2 import Track
from http_client.http_client import HttpClient


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


def apply_metadata(output_path: Path, track: Track, http_client: HttpClient) -> None:
    audio = OggVorbis(output_path)
    audio.clear()

    def set_tag(key: str, value):
        if value is None:
            return
        if isinstance(value, (list, tuple, set)):
            values = [str(v) for v in value if v is not None]
            if values:
                audio[key] = values
        else:
            audio[key] = [str(value)]

    def add_tag(key: str, value):
        if value is None:
            return
        if key not in audio:
            audio[key] = []
        audio[key].append(str(value))

    set_tag("TITLE", track.name)

    if track.original_title and track.original_title != track.name:
        set_tag("ORIGINALTITLE", track.original_title)

    set_tag("TRACKNUMBER", track.number)
    set_tag("DISCNUMBER", track.disc_number)

    if track.version_title:
        set_tag("VERSION", track.version_title)

    if track.artist:
        set_tag("ARTIST", [a.name for a in track.artist if a.name])

    for ext in track.external_id:
        t = ext.type.lower()
        if t == "isrc":
            set_tag("ISRC", ext.id)
        elif t in ("upc", "ean"):
            set_tag("BARCODE", ext.id)
        else:
            add_tag(f"SPOTIFY_{ext.type.upper()}", ext.id)

    if track.explicit:
        set_tag("CONTENTRATING", "Explicit")

    if track.content_rating:
        for cr in track.content_rating:
            for tag in cr.tag:
                add_tag("CONTENTRATING", tag)

    if track.language_of_performance:
        set_tag("LANGUAGE", track.language_of_performance)

    if track.album:
        set_tag("ALBUM", track.album.name)

        if track.album.artist:
            set_tag("ALBUMARTIST", [a.name for a in track.album.artist if a.name])

        if track.album.label:
            set_tag("ORGANIZATION", track.album.label)

        if track.album.genre:
            set_tag("GENRE", track.album.genre)

        if track.album.date and track.album.date.year:
            y = track.album.date.year
            m = getattr(track.album.date, "month", 0)
            d = getattr(track.album.date, "day", 0)

            if m and d:
                set_tag("DATE", f"{y:04d}-{m:02d}-{d:02d}")
            elif m:
                set_tag("DATE", f"{y:04d}-{m:02d}")
            else:
                set_tag("DATE", str(y))

        if track.album.copyright:
            for c in track.album.copyright:
                add_tag("COPYRIGHT", c.text)

    cover_bytes = _download_largest_cover(track, http_client)
    if cover_bytes:
        picture = Picture()
        picture.type = 3
        picture.mime = "image/jpeg"
        picture.desc = "Cover"
        picture.data = cover_bytes

        encoded = base64.b64encode(picture.write()).decode("ascii")
        audio["metadata_block_picture"] = [encoded]

    if track.canonical_uri:
        set_tag("SPOTIFY_URI", track.canonical_uri)

    if track.popularity is not None:
        set_tag("SPOTIFY_POPULARITY", track.popularity)

    audio.save()
