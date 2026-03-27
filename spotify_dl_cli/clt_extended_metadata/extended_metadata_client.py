import uuid
from collections.abc import Iterable
from urllib.parse import urljoin

from spotify_dl_cli.clt_extended_metadata.audio_files_extension_pb2 import (
    AudioFilesExtensionResponse,
)
from spotify_dl_cli.http_client.http_client import HttpClient
from spotify_dl_cli.spotify_uri_helpers import parse_spotify_uri

from .extendedmetadata_pb2 import (
    BatchedEntityRequest,
    BatchedExtensionResponse,
    EntityRequest,
    ExtensionKind,
    ExtensionQuery,
    Track,
)


class ExtendedMetadataClient:
    _ENDPOINT_PATH = "/extended-metadata/v0/extended-metadata"

    def __init__(self, sp_client_base: str, http: HttpClient) -> None:
        self._http = http
        self._base_url = sp_client_base

    def fetch_track(self, uri: str) -> tuple[Track, AudioFilesExtensionResponse]:
        parse_spotify_uri(uri, expected_type="track")
        return self.fetch_tracks([uri])[uri]

    def fetch_tracks(self, uris: Iterable[str]) -> dict[str, tuple[Track, AudioFilesExtensionResponse]]:
        self._validate_track_uris(uris)

        payload = self._build_tracks_request(uris)
        url = self._build_url()

        response = self._http.post_protobuf(url, payload)
        return self._parse_tracks_response(response.content)

    def _build_url(self) -> str:
        return urljoin(self._base_url, self._ENDPOINT_PATH)

    @staticmethod
    def _validate_track_uris(uris: Iterable[str]) -> None:
        if not isinstance(uris, Iterable):
            raise TypeError("uris must be an iterable of Spotify track URIs")

        for uri in uris:
            parse_spotify_uri(uri, expected_type="track")

    @staticmethod
    def _build_tracks_request(uris: Iterable[str]) -> bytes:
        request = BatchedEntityRequest()
        request.header.task_id = uuid.uuid4().bytes

        track_query = ExtensionQuery(extension_kind=ExtensionKind.TRACK_V4)
        audio_query = ExtensionQuery(extension_kind=ExtensionKind.AUDIO_FILES)

        for uri in uris:
            request.entity_request.append(EntityRequest(entity_uri=uri, query=[track_query, audio_query]))

        return request.SerializeToString()

    @staticmethod
    def _parse_tracks_response(
        blob: bytes,
    ) -> dict[str, tuple[Track, AudioFilesExtensionResponse]]:
        response = BatchedExtensionResponse()
        response.ParseFromString(blob)

        tracks: dict[str, Track] = {}
        audio_files: dict[str, AudioFilesExtensionResponse] = {}

        for group in response.extended_metadata:
            if group.extension_kind == ExtensionKind.TRACK_V4:
                for entity in group.extension_data:
                    track = Track()
                    track.ParseFromString(entity.extension_data.value)
                    tracks[entity.entity_uri] = track

            elif group.extension_kind == ExtensionKind.AUDIO_FILES:
                for entity in group.extension_data:
                    audio = AudioFilesExtensionResponse()
                    audio.ParseFromString(entity.extension_data.value)
                    audio_files[entity.entity_uri] = audio

        results: dict[str, tuple[Track, AudioFilesExtensionResponse]] = {}

        for uri in tracks.keys() & audio_files.keys():
            results[uri] = (tracks[uri], audio_files[uri])

        return results
