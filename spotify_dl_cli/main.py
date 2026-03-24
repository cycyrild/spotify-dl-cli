import logging
from humanize import precisedelta
from datetime import timedelta
from pathlib import Path
from spotify_dl_cli.clt_playlist.playlist_client import PlaylistClient
from spotify_dl_cli.playplay_emulator5.key_emu import KeyEmu
from spotify_dl_cli.resolve_exe_path import bundled_dll_path
from spotify_dl_cli.config import default_tokens_path
from spotify_dl_cli.sp_auth.constants import CLIENT_ID
from spotify_dl_cli.sp_downloader.downloader import download_track
from spotify_dl_cli.collect_track_uris import resolve_track_uris
from spotify_dl_cli.parse_args import parse_args
from spotify_dl_cli.clt_playplay.playplay_client import PlayplayClient
from spotify_dl_cli.http_client.http_client import HttpClient
from spotify_dl_cli.clt_extended_metadata.extended_metadata_client import (
    ExtendedMetadataClient,
)
from spotify_dl_cli.clt_storage_resolve.storage_resolve_client import (
    StorageResolverClient,
)
from spotify_dl_cli.service_resolver import resolve_spotify_endpoints
from spotify_dl_cli.sp_auth.pkce import SpotifyAuthPKCE
from spotify_dl_cli.token_manager import SpotifyTokenManager
from spotify_dl_cli.audio_formats import cli_to_format
from spotify_dl_cli.playplay_emulator5.consts import PLAYPLAY_TOKEN

logger = logging.getLogger(__name__)


def main() -> None:
    args = parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level), format="%(levelname)s: %(message)s"
    )

    base_dir = Path(args.output_dir)

    if not base_dir.exists():
        logger.debug("Output directory does not exist. Creating: %s", base_dir)
        base_dir.mkdir(parents=True, exist_ok=True)

    # OAuth 2.0 + PKCE
    auth_pkce = SpotifyAuthPKCE(
        client_id=CLIENT_ID,
        scopes=(
            "playlist-read-private "
            "playlist-modify-private "
            "playlist-modify-public "
            "user-read-email"
        ),
        server_port=5588,
    )

    tokens_file = default_tokens_path()
    logger.debug("Using tokens file: %s", tokens_file)

    token_manager = SpotifyTokenManager(CLIENT_ID, tokens_file, auth_pkce)

    audio_format = cli_to_format(args.quality)

    exe_path = bundled_dll_path()
    logger.debug("Using sp_client dll: %s", exe_path)

    keygen = KeyEmu(exe_path)
    sp_endpoints = resolve_spotify_endpoints()

    if not sp_endpoints.spclient:
        raise RuntimeError("No spclient endpoints available")

    sp_client_base = sp_endpoints.spclient[0]
    logger.debug("Using spclient endpoint: %s", sp_client_base)

    access_token = token_manager.get_access_token()

    client = HttpClient(access_token)
    metadata = ExtendedMetadataClient(sp_client_base, client)
    resolver = StorageResolverClient(sp_client_base, client)
    playplay = PlayplayClient(sp_client_base, PLAYPLAY_TOKEN.VALUE, client)
    playlist_client = PlaylistClient(sp_client_base, client)

    all_track_uris = resolve_track_uris(args.uris, playlist_client)

    if not all_track_uris:
        logger.error("No tracks resolved")
        raise SystemExit(1)

    tracks = metadata.fetch_tracks(all_track_uris)

    for uri, (track, audio_files) in tracks.items():
        duration_str = precisedelta(timedelta(milliseconds=track.duration))

        logger.info("Track    : %s", track.name)
        logger.info("Artist   : %s", ", ".join(a.name for a in track.artist))
        logger.info("Album    : %s", track.album.name)
        logger.info("Duration : %s", duration_str)

        download_track(
            client,
            base_dir,
            track,
            audio_files,
            resolver,
            playplay,
            keygen,
            audio_format,
            args.filename_template,
        )


if __name__ == "__main__":
    main()
