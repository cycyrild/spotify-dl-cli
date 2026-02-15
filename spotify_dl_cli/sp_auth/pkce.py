import base64
import hashlib
import os
import threading
import urllib.parse
from http.server import HTTPServer
from queue import Queue
from spotify_dl_cli.sp_auth.auth_request_pkce import AuthorizationRequestPKCE
from spotify_dl_cli.sp_auth.authorization_code_payload import AuthorizationCodePayload
from spotify_dl_cli.sp_auth.pkce_cb_handler import make_callback_handler


class SpotifyAuthPKCE:
    _AUTH_URL = "https://accounts.spotify.com/authorize"
    _SERVER_HOST = "127.0.0.1"

    def __init__(self, client_id: str, scopes: str, server_port: int):
        self._client_id = client_id
        self._scopes = scopes
        self._server_port = server_port

        self._redirect_uri = f"http://{self._SERVER_HOST}:{self._server_port}/login"

        self._code_verifier = self._generate_code_verifier()
        self._code_challenge = self._generate_code_challenge(self._code_verifier)

        self._auth_code_queue: Queue[str] = Queue(maxsize=1)

    @staticmethod
    def _generate_code_verifier() -> str:
        return base64.urlsafe_b64encode(os.urandom(64)).decode().rstrip("=")

    @staticmethod
    def _generate_code_challenge(verifier: str) -> str:
        digest = hashlib.sha256(verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")

    def get_authorization_url(self) -> str:
        params = AuthorizationRequestPKCE(
            client_id=self._client_id,
            response_type="code",
            redirect_uri=self._redirect_uri,
            scope=self._scopes,
            code_challenge=self._code_challenge,
            code_challenge_method="S256",
        )
        return f"{self._AUTH_URL}?{urllib.parse.urlencode(params)}"

    def start_callback_server(self):
        handler_cls = make_callback_handler(self._auth_code_queue)

        threading.Thread(
            target=lambda: HTTPServer(
                (self._SERVER_HOST, self._server_port), handler_cls
            ).handle_request(),
            daemon=True,
        ).start()

    def wait_for_authorization_code(self, timeout: float | None = None) -> str:
        return self._auth_code_queue.get(timeout=timeout)

    def get_token_exchange_payload(
        self, authorization_code: str
    ) -> AuthorizationCodePayload:
        return AuthorizationCodePayload(
            grant_type="authorization_code",
            code=authorization_code,
            redirect_uri=self._redirect_uri,
            client_id=self._client_id,
            code_verifier=self._code_verifier,
        )
