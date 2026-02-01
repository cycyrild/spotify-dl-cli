import requests
from typing import Optional
from constants import USER_AGENT


class HttpClient:
    def __init__(
        self,
        bearer: str,
    ):
        self.session = requests.Session()
        self.session.verify = True

        headers = {
            "user-agent": USER_AGENT,
        }

        if bearer:
            headers["authorization"] = f"Bearer {bearer}"

        self.session.headers.update(headers)

    def with_protobuf(self) -> "HttpClient":
        client = HttpClient.__new__(HttpClient)
        client.session = self.session
        client.session.headers.update(
            {
                "accept": "application/protobuf",
                "content-type": "application/protobuf",
            }
        )
        return client

    def get(self, url: str, **kwargs) -> requests.Response:
        resp = self.session.get(url, **kwargs)
        resp.raise_for_status()
        return resp

    def post(self, url: str, **kwargs) -> requests.Response:
        resp = self.session.post(url, **kwargs)
        resp.raise_for_status()
        return resp

    def stream(self, url: str, **kwargs):
        return self.session.get(url, stream=True, **kwargs)
