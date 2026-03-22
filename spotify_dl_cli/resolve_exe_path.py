from pathlib import Path
import spotify_dl_cli.playplay_emulator5 as playplay_emulator5

DEFAULT_SPOTIFY_CLIENT_DLL_NAME = "sp_client.dll"


def bundled_dll_path() -> Path:
    package_dir = Path(playplay_emulator5.__file__).resolve().parent
    exe_path = package_dir / DEFAULT_SPOTIFY_CLIENT_DLL_NAME

    if not exe_path.is_file():
        raise FileNotFoundError(
            f"Bundled dll is missing: {exe_path}. Reinstall the package."
        )

    return exe_path
