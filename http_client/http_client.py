import requests
from .constants import *


class HttpClient:

    def __init__(self, bearer: str | None = None):
        self._session = requests.Session()
        self._session.verify = True

        headers = BASE_HEADERS.copy()

        if bearer:
            headers["authorization"] = f"Bearer {bearer}"

        self._session.headers.update(headers)

    def get_protobuf(self, url: str, *, headers: dict | None = None, **kwargs) -> bytes:
        req_headers = {"accept": "application/x-protobuf"}

        if headers:
            req_headers.update(headers)

        resp = self._session.get(url, headers=req_headers, **kwargs)
        resp.raise_for_status()
        return resp.content

    def post_protobuf(
        self, url: str, payload: bytes, *, headers: dict | None = None, **kwargs
    ) -> requests.Response:
        req_headers = {"content-type": "application/x-protobuf"}

        if headers:
            req_headers.update(headers)

        resp = self._session.post(url, data=payload, headers=req_headers, **kwargs)
        resp.raise_for_status()
        return resp

    def head(self, url: str, **kwargs) -> requests.Response:
        resp = self._session.head(url, **kwargs)
        resp.raise_for_status()
        return resp

    def stream(self, url: str, **kwargs):
        return self._session.get(url, stream=True, **kwargs)

    def get(self, url: str, **kwargs) -> requests.Response:
        resp = self._session.get(url, **kwargs)
        resp.raise_for_status()
        return resp
