import uuid
from collections.abc import Iterable
from typing import Dict

from proto.track_pb2 import (
    BatchedEntityRequest,
    BatchedExtensionResponse,
    EntityRequest,
    ExtensionKind,
    ExtensionQuery,
    Track,
)

from constants import EXTENDED_METADATA_ENDPOINT
from http_client import HttpClient

class ExtendedMetadataClient:
    def __init__(self, http: HttpClient):
        self._http = http

    def fetch_tracks(self, uris: Iterable[str]) -> Dict[str, Track]:
        payload = self._build_tracks_request(uris)

        resp = self._http.post(
            EXTENDED_METADATA_ENDPOINT,
            data=payload,
        )

        return self._parse_tracks_response(resp.content)

    @staticmethod
    def _build_tracks_request(uris: Iterable[str]) -> bytes:
        request = BatchedEntityRequest()
        request.header.task_id = uuid.uuid4().bytes

        query = ExtensionQuery(extension_kind=ExtensionKind.TRACK_V4)

        for uri in uris:
            request.entity_request.append(
                EntityRequest(
                    entity_uri=uri,
                    query=[query],
                )
            )

        return request.SerializeToString()

    @staticmethod
    def _parse_tracks_response(blob: bytes) -> Dict[str, Track]:
        response = BatchedExtensionResponse()
        response.ParseFromString(blob)

        tracks: Dict[str, Track] = {}

        for array in response.extended_metadata:
            if array.extension_kind != ExtensionKind.TRACK_V4:
                continue

            for entity in array.extension_data:
                track = Track()
                track.ParseFromString(entity.extension_data.value)
                tracks[entity.entity_uri] = track

        return tracks
