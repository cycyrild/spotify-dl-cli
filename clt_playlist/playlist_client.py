from urllib.parse import urljoin, urlencode, urlparse, parse_qsl, urlunparse
from typing import List, Optional
from http_client.http_client import HttpClient
from clt_playlist.playlist4_external_pb2 import SelectedListContent


class PlaylistClient:
    _ENDPOINT_TEMPLATE = "/playlist/v2/playlist/{playlist_id}"
    _URI_PREFIX = "spotify:playlist:"

    def __init__(self, sp_client_base: str, http: HttpClient) -> None:
        self._base_url = sp_client_base
        self._http = http

    def fetch_all_track_uris(self, playlist_uri: str) -> List[str]:
        playlist_id = self._extract_playlist_id(playlist_uri)
        url = self._build_url(playlist_id)

        uris: List[str] = []

        while url:
            response = self._http.get_protobuf(url)

            content = SelectedListContent()
            content.ParseFromString(response)

            uris.extend(self._extract_uris(content))
            url = self._get_next_page(url, content)

        return uris

    def _build_url(self, playlist_id: str) -> str:
        path = self._ENDPOINT_TEMPLATE.format(playlist_id=playlist_id)
        return urljoin(self._base_url, path)

    @classmethod
    def _extract_playlist_id(cls, playlist_uri: str) -> str:
        if not playlist_uri.startswith(cls._URI_PREFIX):
            raise ValueError(f"Invalid Spotify playlist URI: {playlist_uri}")

        parts = playlist_uri.split(":")
        if len(parts) != 3:
            raise ValueError(f"Malformed Spotify playlist URI: {playlist_uri}")

        return parts[2]

    @staticmethod
    def _extract_uris(content: SelectedListContent) -> List[str]:
        uris: List[str] = []

        if not content.HasField("contents"):
            return uris

        for item in content.contents.items:
            if item.uri.startswith("spotify:track:"):
                uris.append(item.uri)

        return uris

    def _get_next_page(
        self, current_url: str, content: SelectedListContent
    ) -> Optional[str]:

        if not content.HasField("contents"):
            return None

        if not content.contents.truncated:
            return None

        pos = content.contents.pos
        items_count = len(content.contents.items)
        length = content.length if content.HasField("length") else None

        new_offset = pos + items_count

        if length is not None and new_offset >= length:
            return None

        return self._update_offset(current_url, new_offset)

    @staticmethod
    def _update_offset(url: str, offset: int) -> str:
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query))
        query["offset"] = str(offset)

        new_query = urlencode(query)
        return urlunparse(parsed._replace(query=new_query))
