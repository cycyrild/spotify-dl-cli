import time
from http_client.http_client import HttpClient
from .playplay_pb2 import (
    ContentType,
    Interactivity,
    PlayPlayLicenseRequest,
    PlayPlayLicenseResponse,
)
from urllib.parse import urljoin


class PlayPlayClient:
    _ENDPOINT_PATH = "/playplay/v1/key"

    def __init__(
        self, sp_client_base: str, playplay_token: bytes, http: HttpClient
    ) -> None:
        self._base_url = sp_client_base
        self._token = playplay_token
        self._http = http

    def get_obfuscated_key(self, file_id: bytes) -> bytes:
        url = self._build_url(file_id)
        payload = self._build_license_request()

        response = self._http.post_protobuf(url, payload)
        return self._parse_license_response(response.content)

    def _build_url(self, file_id: bytes) -> str:
        return urljoin(self._base_url, f"{self._ENDPOINT_PATH}/{file_id.hex()}")

    def _build_license_request(self) -> bytes:
        request = PlayPlayLicenseRequest()
        request.version = 3
        request.token = self._token
        request.interactivity = Interactivity.INTERACTIVE
        request.content_type = ContentType.AUDIO_TRACK
        request.timestamp = int(time.time())

        return request.SerializeToString()

    @staticmethod
    def _parse_license_response(blob: bytes) -> bytes:
        response = PlayPlayLicenseResponse()
        response.ParseFromString(blob)

        if not response.obfuscated_key:
            raise RuntimeError("playplay: empty obfuscated_key")

        return response.obfuscated_key
