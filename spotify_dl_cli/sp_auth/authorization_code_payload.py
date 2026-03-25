from typing import Literal, TypedDict


class AuthorizationCodePayload(TypedDict):
    grant_type: Literal["authorization_code"]
    code: str
    redirect_uri: str
    client_id: str
    code_verifier: str
