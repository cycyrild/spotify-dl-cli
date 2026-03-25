import logging
from collections.abc import Iterable

from spotify_dl_cli.clt_playlist.playlist_client import PlaylistClient
from spotify_dl_cli.spotify_uri_helpers import parse_spotify_uri

logger = logging.getLogger(__name__)


def resolve_track_uris(uris: Iterable[str], playlist_client: PlaylistClient) -> set[str]:
    all_track_uris: set[str] = set()

    for uri in uris:
        try:
            resource_type, _ = parse_spotify_uri(uri)
        except (TypeError, ValueError) as e:
            logger.error("Invalid URI: %s (%s)", uri, e)
            continue

        if resource_type == "track":
            all_track_uris.add(uri)

        elif resource_type == "playlist":
            logger.info("Fetching playlist: %s", uri)
            playlist_uris = playlist_client.fetch_all_track_uris(uri)
            logger.info("Found %d tracks", len(playlist_uris))
            all_track_uris.update(playlist_uris)

        else:
            logger.warning("Unsupported Spotify resource type: %s", resource_type)

    return all_track_uris
