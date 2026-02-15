SPOTIFY_APP_VERSION = "1.2.36.959".replace(".", "")
USER_AGENT = (
    f"Spotify/{SPOTIFY_APP_VERSION} Win32/Windows 10 (10.0.19044; x86[native:x64])"
)
APP_PLATFORM = "Win32"

BASE_HEADERS = {
    "user-agent": USER_AGENT,
    "spotify-app-version": SPOTIFY_APP_VERSION,
    "app-platform": APP_PLATFORM,
}
