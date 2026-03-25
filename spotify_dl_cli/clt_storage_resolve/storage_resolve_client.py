from urllib.parse import urljoin

from spotify_dl_cli.clt_extended_metadata.extendedmetadata_pb2 import AudioFile
from spotify_dl_cli.clt_storage_resolve.storage_resolve_pb2 import (
    StorageResolveResponse,
)
from spotify_dl_cli.http_client.http_client import HttpClient


class StorageResolverClient:
    _ENDPOINT_PATH = "/storage-resolve/v2/files/audio/interactive"

    def __init__(self, sp_client_base: str, http: HttpClient) -> None:
        self._http = http
        self._base_url = sp_client_base

    def resolve(self, file_id: bytes, format: AudioFile.Format) -> list[str]:
        url = self._build_url(file_id, format)
        response = self._http.get_protobuf(url)
        return self._parse_response(response)

    def _build_url(self, file_id: bytes, format: AudioFile.Format) -> str:
        return urljoin(self._base_url, f"{self._ENDPOINT_PATH}/{format}/{file_id.hex()}")

    @staticmethod
    def _parse_response(blob: bytes) -> list[str]:
        response = StorageResolveResponse()
        response.ParseFromString(blob)

        if response.result != StorageResolveResponse.CDN:
            raise RuntimeError(f"storage-resolve failed: result={response.result}")

        return list(response.cdnurl)
