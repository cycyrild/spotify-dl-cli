import logging
from pathlib import Path
from platformdirs import user_config_dir

DEFAULT_TOKENS_FILE_NAME = "spotify_tokens.json"
APP_NAME = "spotify-dl-cli"

logger = logging.getLogger(__name__)


def default_tokens_path() -> Path:
    config_dir = Path(user_config_dir(APP_NAME))
    return config_dir / DEFAULT_TOKENS_FILE_NAME


def resolve_tokens_path(tokens_file_arg: str | None) -> Path:
    if tokens_file_arg:
        logger.debug("Resolving custom tokens file path: %s", tokens_file_arg)
        return Path(tokens_file_arg).expanduser().resolve()
    return default_tokens_path()
