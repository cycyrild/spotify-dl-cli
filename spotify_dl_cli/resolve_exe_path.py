from pathlib import Path

import spotify_dl_cli as spotify_dl_cli
from spotify_dl_cli.consts import SPOTIFY_APP_VERSION

DEFAULT_SPOTIFY_CLIENT_DLL_NAME = "sp_client.dll"


def bundled_dll_path() -> Path:
    package_dir = Path(spotify_dl_cli.__file__).resolve().parent
    dll_path = package_dir / DEFAULT_SPOTIFY_CLIENT_DLL_NAME

    if not dll_path.is_file():
        raise FileNotFoundError(f"DLL for client version {SPOTIFY_APP_VERSION} is missing: {dll_path}")

    return dll_path
