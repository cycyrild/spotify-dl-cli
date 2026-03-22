from pathlib import Path
import spotify_dl_cli.playplay_emulator5 as playplay_emulator5

DEFAULT_SPOTIFY_CLIENT_EXE_NAME = "sp_client.exe"


def bundled_exe_path() -> Path:
    package_dir = Path(playplay_emulator5.__file__).resolve().parent
    exe_path = package_dir / DEFAULT_SPOTIFY_CLIENT_EXE_NAME

    if not exe_path.is_file():
        raise FileNotFoundError(
            f"Bundled executable is missing: {exe_path}. Reinstall the package."
        )

    return exe_path
