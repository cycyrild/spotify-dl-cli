import json
import logging
import time
import requests
from pathlib import Path
from typing import Optional
from spotify_dl_cli.http_client.constants import BASE_HEADERS
from spotify_dl_cli.sp_auth.pkce import SpotifyAuthPKCE
from spotify_dl_cli.sp_auth.refresh_token_payload import RefreshTokenPayload
from spotify_dl_cli.sp_auth.tokens import SpotifyTokens

logger = logging.getLogger(__name__)


class SpotifyTokenManager:
    _TOKEN_URL = "https://accounts.spotify.com/api/token"

    def __init__(
        self, client_id: str, token_file: Path, auth_provider: SpotifyAuthPKCE
    ):
        self._client_id = client_id
        self._token_file = token_file
        self._auth_provider = auth_provider
        self._tokens: Optional[SpotifyTokens] = None

    def _load_tokens(self) -> Optional[SpotifyTokens]:
        if self._token_file.exists():
            with self._token_file.open("r") as f:
                self._tokens = json.load(f)
                return self._tokens
        return None

    def _save_tokens(self, tokens: SpotifyTokens) -> None:
        self._token_file.parent.mkdir(parents=True, exist_ok=True)
        with self._token_file.open("w") as f:
            json.dump(tokens, f, indent=2)
        self._tokens = tokens

    def is_token_valid(self) -> bool:
        if not self._tokens:
            return False

        expires_at = self._tokens.get("expires_at")
        return bool(expires_at and expires_at > time.time())

    def refresh_token(self) -> SpotifyTokens:
        if self._tokens is None:
            raise RuntimeError("No tokens available for refresh")

        response = requests.post(
            self._TOKEN_URL,
            headers=BASE_HEADERS,
            data=RefreshTokenPayload(
                grant_type="refresh_token",
                refresh_token=self._tokens["refresh_token"],
                client_id=self._client_id,
            ),
        )

        if response.status_code == 400:
            body = response.json()
            raise RuntimeError(
                f"Spotify token refresh failed ({body.get('error')}): "
                f"{body.get('error_description')}"
            )

        response.raise_for_status()

        tokens: SpotifyTokens = response.json()

        if "refresh_token" not in tokens:
            raise RuntimeError("Spotify token refresh response missing refresh_token")

        self._set_expiry(tokens)
        logger.info(
            "Refreshed access token, expires in %d seconds", tokens["expires_in"]
        )
        self._save_tokens(tokens)

        return tokens

    def first_authentication(self) -> SpotifyTokens:
        self._auth_provider.start_callback_server()
        logger.warning("Open the following URL to authorize Spotify access:")
        logger.warning("%s", self._auth_provider.get_authorization_url())

        code = self._auth_provider.wait_for_authorization_code(timeout=300)
        payload = self._auth_provider.get_token_exchange_payload(code)

        response = requests.post(self._TOKEN_URL, headers=BASE_HEADERS, data=payload)
        response.raise_for_status()

        tokens: SpotifyTokens = response.json()
        self._set_expiry(tokens)
        logger.info(
            "Obtained new access token, expires in %d seconds", tokens["expires_in"]
        )
        self._save_tokens(tokens)
        return tokens

    def get_access_token(self) -> str:
        if self._tokens is None:
            self._load_tokens()

        if self._tokens and self.is_token_valid():
            return self._tokens["access_token"]

        if self._tokens and "refresh_token" in self._tokens:
            tokens = self.refresh_token()
            return tokens["access_token"]

        tokens = self.first_authentication()
        return tokens["access_token"]

    def _set_expiry(self, tokens: SpotifyTokens) -> None:
        tokens["expires_at"] = int(time.time()) + tokens["expires_in"]
