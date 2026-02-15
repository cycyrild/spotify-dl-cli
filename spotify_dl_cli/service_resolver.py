import requests
from typing import List, NamedTuple
from urllib.parse import urlparse
from spotify_dl_cli.http_client.constants import BASE_HEADERS


class SpotifyEndpoints(NamedTuple):
    dealer: List[str]
    spclient: List[str]


APRESOLVE_URL = "https://apresolve.spotify.com/"
DEFAULT_SCHEME = "https"


def parse_endpoint(raw: str, *, scheme: str = DEFAULT_SCHEME) -> str:
    parsed = urlparse(f"{scheme}://{raw}")

    if parsed.scheme != scheme or not parsed.netloc:
        raise ValueError(f"Invalid endpoint format: {raw}")

    return f"{parsed.scheme}://{parsed.netloc}/"


def resolve_spotify_endpoints() -> SpotifyEndpoints:
    r = requests.get(
        APRESOLVE_URL, headers=BASE_HEADERS, params={"type": ("dealer", "spclient")}
    )
    r.raise_for_status()
    data = r.json()

    return SpotifyEndpoints(
        dealer=[parse_endpoint(e) for e in data.get("dealer", [])],
        spclient=[parse_endpoint(e) for e in data.get("spclient", [])],
    )
