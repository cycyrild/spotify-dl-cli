import logging
import time
import requests
from tenacity import (
    retry,
    wait_exponential,
    stop_after_attempt,
    retry_if_exception,
    before_sleep_log,
)
from spotify_dl_cli.http_client.http_client import HttpClient
from .playplay_pb2 import (
    ContentType,
    Interactivity,
    PlayPlayLicenseRequest,
    PlayPlayLicenseResponse,
)
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


class PlayplayClient:
    _ENDPOINT_PATH = "/playplay/v1/key"

    def __init__(
        self, sp_client_base: str, playplay_token: bytes, http: HttpClient
    ) -> None:
        self._base_url = sp_client_base
        self._token = playplay_token
        self._http = http

    @staticmethod
    def _is_403_error(exception):
        return (
            isinstance(exception, requests.exceptions.HTTPError)
            and exception.response is not None
            and exception.response.status_code == 403
        )

    @retry(
        retry=retry_if_exception(_is_403_error),
        wait=wait_exponential(multiplier=5, min=5),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        stop=stop_after_attempt(8),
        reraise=True,
    )
    def get_obfuscated_key(self, file_id: bytes) -> bytes:
        url = self._build_url(file_id)
        payload = self._build_license_request()
        response = self._http.post_protobuf(url, payload)
        return self._parse_license_response(response.content)

    def _build_url(self, file_id: bytes) -> str:
        return urljoin(self._base_url, f"{self._ENDPOINT_PATH}/{file_id.hex()}")

    def _build_license_request(self) -> bytes:
        request = PlayPlayLicenseRequest()
        request.version = 5
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
