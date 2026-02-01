import time
from constants import PLAYPLAY_ENDPOINT
from http_client import HttpClient
from proto.playplay_pb2 import (
    ContentType,
    Interactivity,
    PlayPlayLicenseRequest,
    PlayPlayLicenseResponse,
)

class PlayPlayClient:
    def __init__(self, http: HttpClient, playplay_token: bytes):
        self._http = http
        self._token = playplay_token

    def get_obfuscated_key(self, file_id: bytes) -> bytes:
        payload = self._build_license_request()
        url = f"{PLAYPLAY_ENDPOINT}/{file_id.hex()}"

        resp = self._http.post(url, data=payload)
        return self._parse_license_response(resp.content)

    def _build_license_request(self) -> bytes:
        req = PlayPlayLicenseRequest()
        req.version = 3
        req.token = self._token
        req.interactivity = Interactivity.INTERACTIVE
        req.content_type = ContentType.AUDIO_TRACK
        req.timestamp = int(time.time())

        return req.SerializeToString()

    @staticmethod
    def _parse_license_response(blob: bytes) -> bytes:
        res = PlayPlayLicenseResponse()
        res.ParseFromString(blob)

        if not res.obfuscated_key:
            raise RuntimeError("playplay: empty obfuscated_key")

        return res.obfuscated_key
