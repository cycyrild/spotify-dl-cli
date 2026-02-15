from pathlib import Path
import playplay_emulator

DEFAULT_SPOTIFY_CLIENT_EXE_NAME = "sp_client.exe"


def _bundled_exe_path() -> Path:
    package_dir = Path(playplay_emulator.__file__).resolve().parent
    exe_path = package_dir / DEFAULT_SPOTIFY_CLIENT_EXE_NAME

    if not exe_path.is_file():
        raise FileNotFoundError(
            f"Bundled executable is missing: {exe_path}. "
            "Reinstall the package or provide --exe-path."
        )

    return exe_path


def resolve_exe_path(exe_path_arg: str | None) -> Path:
    if exe_path_arg:
        candidate = Path(exe_path_arg).expanduser()
        if candidate.is_file():
            return candidate.resolve()
        raise FileNotFoundError(
            f"Unable to find executable from --exe-path: {candidate}. "
            "Please provide a valid path."
        )

    return _bundled_exe_path()
