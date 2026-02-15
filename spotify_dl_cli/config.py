from pathlib import Path
from platformdirs import user_config_dir

DEFAULT_TOKENS_FILE_NAME = "spotify_tokens.json"
APP_NAME = "spotify-dl-cli"


def default_tokens_path() -> Path:
    config_dir = Path(user_config_dir(APP_NAME))
    return config_dir / DEFAULT_TOKENS_FILE_NAME
