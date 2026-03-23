from spotify_dl_cli.consts import SPOTIFY_APP_VERSION

SP_VERSION_FORMATTED = SPOTIFY_APP_VERSION.replace(".", "")

USER_AGENT = f"Spotify/{SP_VERSION_FORMATTED} Win32_x86_64/Windows 10 (10.0.19044; x64)"
APP_PLATFORM = "Win32"

BASE_HEADERS = {
    "user-agent": USER_AGENT,
    "spotify-app-version": SP_VERSION_FORMATTED,
    "app-platform": APP_PLATFORM,
}
