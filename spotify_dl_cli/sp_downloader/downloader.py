import logging
from pathlib import Path
from humanize import naturalsize
from spotify_dl_cli.http_client.http_client import HttpClient
from spotify_dl_cli.clt_playplay.playplay_client import PlayPlayClient
from spotify_dl_cli.playplay_emulator.keygen import PlayPlayKeygen
from spotify_dl_cli.clt_extended_metadata.extendedmetadata_pb2 import AudioFile, Track
from spotify_dl_cli.sp_downloader.generate_output_filename import (
    generate_output_filename,
)
from spotify_dl_cli.sp_downloader.apply_metadata import apply_metadata
from spotify_dl_cli.clt_storage_resolve.storage_resolve_client import (
    StorageResolverClient,
)
from tqdm import tqdm

logger = logging.getLogger(__name__)

from .helpers import download_decrypt_and_reconstruct, iter_audio_files


def _download_from_url(
    http_client: HttpClient, url: str, output_path: Path, keygen: PlayPlayKeygen
) -> None:
    head = http_client.head(url)
    total_size = int(head.headers["Content-Length"])

    logger.info("Estimated file size: %s", naturalsize(total_size, binary=True))
    logger.info("Downloading: %s", output_path)

    with (
        open(output_path, "wb") as f,
        tqdm(
            total=total_size, unit="B", unit_scale=True, unit_divisor=1024, leave=False
        ) as pbar,
    ):
        for ogg_page in download_decrypt_and_reconstruct(http_client, url, keygen):
            size = len(ogg_page)
            f.write(ogg_page)
            pbar.update(size)


def download_track(
    http_client: HttpClient,
    output_dir: Path,
    track: Track,
    resolver: StorageResolverClient,
    playplay: PlayPlayClient,
    keygen: PlayPlayKeygen,
    audio_format: AudioFile.Format,
    track_filename_template: str,
) -> None:

    audio_files = list(iter_audio_files(track))

    logger.debug(
        "Available formats: %s", [AudioFile.Format.Name(f.format) for f in audio_files]
    )

    file = next((f for f in audio_files if f.format == audio_format), None)

    if not file:
        logger.warning("Audio format unavailable, skipping track")
        return

    logger.debug("File ID: %s", file.file_id.hex())

    obfuscated_key = playplay.get_obfuscated_key(file.file_id)
    logger.debug("Obfuscated key: %s", obfuscated_key.hex())

    keygen.configure(file_id=file.file_id, obfuscated_key=obfuscated_key)
    logger.debug("Keygen configured with derived key: %s", keygen.derived_key.hex())

    urls = resolver.resolve(file.file_id)

    if not urls:
        raise RuntimeError("No URL returned by the resolver")

    output_path = f"{generate_output_filename(track, track_filename_template)}.ogg"
    output_path = output_dir / output_path

    last_error = None
    downloaded = False
    for idx, url in enumerate(urls, start=1):
        try:
            _download_from_url(http_client, url, output_path, keygen)

        except Exception as exc:
            last_error = exc

            if output_path.exists():
                output_path.unlink()

            logger.warning(
                "Download failed for URL %s/%s, trying next if available: %s (%s)",
                idx,
                len(urls),
                url,
                exc,
            )
            continue

        downloaded = True
        break

    if not downloaded:
        raise RuntimeError("All download URLs failed") from last_error

    logger.debug("Applying metadata tags ...")
    apply_metadata(output_path, track, http_client)

    logger.info("Download completed: %s", output_path)
