from typing import TypedDict, Literal, NotRequired


class AuthorizationRequestPKCE(TypedDict):
    client_id: str
    response_type: Literal["code"]
    redirect_uri: str
    scope: str
    code_challenge: str
    code_challenge_method: Literal["S256"]
    state: NotRequired[str]
