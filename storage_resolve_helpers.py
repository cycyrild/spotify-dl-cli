from typing import List
from constants import STORAGE_RESOLVE_V2_ENDPOINT
from http_client import HttpClient
from proto.storage_resolve_pb2 import StorageResolveResponse

class StorageResolver:
    def __init__(self, http: HttpClient):
        self._http = http

    def resolve(self, file_id: bytes) -> List[str]:
        url = f"{STORAGE_RESOLVE_V2_ENDPOINT}/{file_id.hex()}"
        resp = self._http.get(url)
        return self._parse_response(resp.content)

    @staticmethod
    def _parse_response(blob: bytes) -> List[str]:
        sr = StorageResolveResponse()
        sr.ParseFromString(blob)

        if sr.result != StorageResolveResponse.CDN:
            raise RuntimeError(f"storage-resolve failed: result={sr.result}")

        return list(sr.cdnurl)
