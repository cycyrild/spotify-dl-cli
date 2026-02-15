from typing import TypedDict


class SpotifyTokens(TypedDict):
    access_token: str
    refresh_token: str
    expires_in: int
    expires_at: int
    token_type: str
    scope: str
