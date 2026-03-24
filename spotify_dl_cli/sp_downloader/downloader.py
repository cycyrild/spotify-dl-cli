import logging
from pathlib import Path
from humanize import naturalsize
from spotify_dl_cli.audio_formats import format_to_cli, format_to_extension
from spotify_dl_cli.http_client.http_client import HttpClient
from spotify_dl_cli.clt_playplay.playplay_client import PlayplayClient
from spotify_dl_cli.clt_extended_metadata.extendedmetadata_pb2 import AudioFile, Track
from spotify_dl_cli.playplay_emulator5.key_emu import KeyEmu
from spotify_dl_cli.sp_downloader.generate_output_filename import (
    generate_output_filename,
)
from spotify_dl_cli.clt_storage_resolve.storage_resolve_client import (
    StorageResolverClient,
)
from tqdm import tqdm
from spotify_dl_cli.sp_downloader.transfer import download_decrypt
from spotify_dl_cli.playplay_emulator5.consts import EMULATOR_SIZES
from spotify_dl_cli.clt_extended_metadata.audio_files_extension_pb2 import (
    AudioFilesExtensionResponse,
    ExtendedAudioFile,
)
from spotify_dl_cli.audio_formats import VORBIS_FORMATS
from spotify_dl_cli.ogg_parser import reconstruct_ogg_from_chunks
from spotify_dl_cli.sp_downloader.apply_metadata import apply_metadata

logger = logging.getLogger(__name__)


def _download_from_url(
    http_client: HttpClient,
    url: str,
    file_format: AudioFile.Format,
    output_path: Path,
    aes_key: bytes,
) -> None:
    head = http_client.head(url)
    total_size = int(head.headers["Content-Length"])

    logger.info("Estimated file size: %s", naturalsize(total_size, binary=True))
    logger.info("Downloading: %s", output_path)

    with (
        output_path.open("wb") as f,
        tqdm(
            total=total_size, unit="B", unit_scale=True, unit_divisor=1024, leave=False
        ) as pbar,
    ):
        chunks = download_decrypt(http_client, url, aes_key)

        if file_format in VORBIS_FORMATS:
            chunks = reconstruct_ogg_from_chunks(chunks)

        for chunk in chunks:
            f.write(chunk)
            pbar.update(len(chunk))


def _download_with_fallback(
    http_client: HttpClient,
    urls: list[str],
    file_format: AudioFile.Format,
    output_path: Path,
    aes_key: bytes,
) -> None:
    last_error = None

    for idx, url in enumerate(urls, start=1):
        try:
            _download_from_url(http_client, url, file_format, output_path, aes_key)
            return
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

    raise RuntimeError("All download URLs failed") from last_error


def download_track(
    http_client: HttpClient,
    output_dir: Path,
    track: Track,
    audio_files: AudioFilesExtensionResponse,
    resolver: StorageResolverClient,
    playplay: PlayplayClient,
    keygen: KeyEmu,
    audio_format: AudioFile.Format,
    track_filename_template: str,
) -> None:
    logger.debug(
        "Available formats: %s",
        [
            fmt
            for f in audio_files.files
            if (fmt := format_to_cli(f.file.format)) is not None
        ],
    )

    extended_file: ExtendedAudioFile | None = next(
        (f for f in audio_files.files if f.file.format == audio_format), None
    )

    if not extended_file:
        logger.warning("Audio format unavailable, skipping track")
        return

    file = extended_file.file

    obfuscated_key = playplay.get_obfuscated_key(file.file_id)
    logger.debug("Obfuscated key: %s", obfuscated_key.hex())

    aes_key = keygen.get_aes_key(
        content_id=file.file_id[: EMULATOR_SIZES.CONTENT_ID],
        obfuscated_key=obfuscated_key,
    )
    logger.info("Download Quality: %s", format_to_cli(file.format))
    logger.info("File ID: %s, AES key: %s", file.file_id.hex(), aes_key.hex())

    urls = resolver.resolve(file.file_id, file.format)

    if not urls:
        raise RuntimeError("No URL returned by the resolver")

    output_path = f"{generate_output_filename(track, track_filename_template)}.{format_to_extension(file.format)}"
    output_path = output_dir / output_path

    _download_with_fallback(http_client, urls, file.format, output_path, aes_key)

    logger.debug("Applying metadata tags ...")
    apply_metadata(output_path, file.format, track, http_client)

    logger.info("Download completed: %s", output_path)
