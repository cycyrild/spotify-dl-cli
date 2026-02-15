from typing import TypedDict


class RefreshTokenPayload(TypedDict):
    grant_type: str
    refresh_token: str
    client_id: str
