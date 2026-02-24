import logging
from humanize import precisedelta
from datetime import timedelta
from pathlib import Path
from spotify_dl_cli.clt_playlist.playlist_client import PlaylistClient
from spotify_dl_cli.resolve_exe_path import bundled_exe_path
from spotify_dl_cli.config import default_tokens_path
from spotify_dl_cli.sp_auth.constants import CLIENT_ID
from spotify_dl_cli.sp_downloader.downloader import download_track
from spotify_dl_cli.parse_args import parse_args
from spotify_dl_cli.clt_playplay.playplay_client import PlayPlayClient
from spotify_dl_cli.http_client.http_client import HttpClient
from spotify_dl_cli.playplay_emulator.keygen import PlayPlayKeygen
from spotify_dl_cli.clt_extended_metadata.extended_metadata_client import (
    ExtendedMetadataClient,
)
from spotify_dl_cli.clt_storage_resolve.storage_resolve_client import (
    StorageResolverClient,
)
from spotify_dl_cli.service_resolver import resolve_spotify_endpoints
from spotify_dl_cli.sp_auth.pkce import SpotifyAuthPKCE
from spotify_dl_cli.spotify_uri_helpers import parse_spotify_uri
from spotify_dl_cli.token_manager import SpotifyTokenManager
from spotify_dl_cli.audio_formats import AUDIO_FORMATS

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

    audio_format = AUDIO_FORMATS[args.quality]

    exe_path = bundled_exe_path()
    logger.debug("Using sp_client executable: %s", exe_path)

    keygen = PlayPlayKeygen(exe_path)
    sp_endpoints = resolve_spotify_endpoints()

    if not sp_endpoints.spclient:
        raise RuntimeError("No spclient endpoints available")

    sp_client_base = sp_endpoints.spclient[0]
    logger.debug("Using spclient endpoint: %s", sp_client_base)

    access_token = token_manager.get_access_token()

    client = HttpClient(access_token)
    metadata = ExtendedMetadataClient(sp_client_base, client)
    resolver = StorageResolverClient(sp_client_base, client)
    playplay = PlayPlayClient(sp_client_base, keygen.playplay_token, client)
    playlist_client = PlaylistClient(sp_client_base, client)

    all_track_uris: set[str] = set()

    for uri in args.uris:
        try:
            resource_type, _ = parse_spotify_uri(uri)
        except (TypeError, ValueError) as e:
            logger.error("Invalid URI: %s (%s)", uri, e)
            continue

        if resource_type == "track":
            all_track_uris.add(uri)

        elif resource_type == "playlist":
            logger.info("Fetching playlist: %s", uri)
            uris = playlist_client.fetch_all_track_uris(uri)
            logger.info("Found %d tracks", len(uris))
            all_track_uris.update(uris)

        else:
            logger.warning("Unsupported Spotify resource type: %s", resource_type)

    if not all_track_uris:
        logger.error("No tracks resolved")
        raise SystemExit(1)

    tracks = metadata.fetch_tracks(all_track_uris)

    for uri, track in tracks.items():
        logger.info("Track    : %s", track.name)
        logger.info("Artist   : %s", ", ".join(a.name for a in track.artist))
        logger.info("Album    : %s", track.album.name)
        logger.info(
            "Duration : %s", precisedelta(timedelta(milliseconds=track.duration))
        )

        download_track(
            client,
            base_dir,
            track,
            resolver,
            playplay,
            keygen,
            audio_format,
            args.filename_template,
        )


if __name__ == "__main__":
    main()
