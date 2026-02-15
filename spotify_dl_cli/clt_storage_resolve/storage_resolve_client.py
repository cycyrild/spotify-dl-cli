from spotify_dl_cli.http_client.http_client import HttpClient
from .storage_resolve_pb2 import StorageResolveResponse
from typing import List
from urllib.parse import urljoin


class StorageResolverClient:
    _ENDPOINT_PATH = "/storage-resolve/v2/files/audio/interactive/1"

    def __init__(self, sp_client_base: str, http: HttpClient) -> None:
        self._http = http
        self._base_url = sp_client_base

    def resolve(self, file_id: bytes) -> List[str]:
        url = self._build_url(file_id)
        response = self._http.get_protobuf(url)
        return self._parse_response(response)

    def _build_url(self, file_id: bytes) -> str:
        return urljoin(self._base_url, f"{self._ENDPOINT_PATH}/{file_id.hex()}")

    @staticmethod
    def _parse_response(blob: bytes) -> List[str]:
        response = StorageResolveResponse()
        response.ParseFromString(blob)

        if response.result != StorageResolveResponse.CDN:
            raise RuntimeError(f"storage-resolve failed: result={response.result}")

        return list(response.cdnurl)
