import time
import uuid
import requests
from typing import Iterable, Dict, List, Optional
import numpy as np

from playplay_emulator.playplay_keygen import PlayPlayKeygen

from proto.track_pb2 import (
    BatchedEntityRequest,
    BatchedExtensionResponse,
    EntityRequest,
    ExtensionQuery,
    ExtensionKind,
    Track,
    AudioFile,
)

from proto.playplay_pb2 import (
    PlayPlayLicenseRequest,
    PlayPlayLicenseResponse,
    Interactivity,
    ContentType,
)

from proto.storage_resolve_pb2 import StorageResolveResponse


SPCLIENT_BASE = "https://gew1-spclient.spotify.com"
EXTENDED_METADATA_ENDPOINT = f"{SPCLIENT_BASE}/extended-metadata/v0/extended-metadata"
STORAGE_RESOLVE_V2_ENDPOINT = (
    f"{SPCLIENT_BASE}/storage-resolve/v2/files/audio/interactive/1"
)
PLAYPLAY_ENDPOINT = f"{SPCLIENT_BASE}/playplay/v1/key"

USER_AGENT = "Spotify/123101205 Win32"
TARGET_AUDIO_FORMAT = AudioFile.Format.OGG_VORBIS_160


def build_headers(bearer: str, protobuf: bool = True) -> dict:
    headers = {
        "authorization": f"Bearer {bearer}",
        "user-agent": USER_AGENT,
    }
    if protobuf:
        headers["accept"] = "application/protobuf"
        headers["content-type"] = "application/protobuf"
    return headers


class PlayPlayClient:
    def __init__(self, bearer: str, keygen: PlayPlayKeygen):
        self.bearer = bearer
        self.keygen = keygen

    def get_obfuscated_key(self, file_id: bytes) -> bytes:
        req = PlayPlayLicenseRequest()
        req.version = 3
        req.token = self.keygen.playplay_token
        req.interactivity = Interactivity.INTERACTIVE
        req.content_type = ContentType.AUDIO_TRACK
        req.timestamp = int(time.time())

        url = f"{PLAYPLAY_ENDPOINT}/{file_id.hex()}"

        resp = requests.post(
            url,
            headers=build_headers(self.bearer),
            data=req.SerializeToString(),
            verify=False,
        )
        resp.raise_for_status()

        res = PlayPlayLicenseResponse()
        res.ParseFromString(resp.content)

        if not res.obfuscated_key:
            raise RuntimeError("playplay: empty obfuscated_key")

        return res.obfuscated_key


class ExtendedMetadataClient:
    def __init__(self, bearer: str):
        self.bearer = bearer

    def fetch_tracks(self, uris: Iterable[str]) -> Dict[str, Track]:
        request = BatchedEntityRequest()
        request.header.task_id = uuid.uuid4().bytes

        query = ExtensionQuery(extension_kind=ExtensionKind.TRACK_V4)

        for uri in uris:
            request.entity_request.append(EntityRequest(entity_uri=uri, query=[query]))

        resp = requests.post(
            EXTENDED_METADATA_ENDPOINT,
            headers=build_headers(self.bearer),
            data=request.SerializeToString(),
            verify=False,
        )
        resp.raise_for_status()

        response = BatchedExtensionResponse()
        response.ParseFromString(resp.content)

        tracks: Dict[str, Track] = {}

        for array in response.extended_metadata:
            if array.extension_kind != ExtensionKind.TRACK_V4:
                continue

            for entity in array.extension_data:
                track = Track()
                track.ParseFromString(entity.extension_data.value)
                tracks[entity.entity_uri] = track

        return tracks


class StorageResolver:
    def __init__(self, bearer: str):
        self.bearer = bearer

    def resolve(self, file_id: bytes) -> List[str]:
        url = f"{STORAGE_RESOLVE_V2_ENDPOINT}/{file_id.hex()}"

        resp = requests.get(url, headers=build_headers(self.bearer))
        resp.raise_for_status()

        sr = StorageResolveResponse()
        sr.ParseFromString(resp.content)

        if sr.result != StorageResolveResponse.CDN:
            raise RuntimeError(f"storage-resolve failed: result={sr.result}")

        return list(sr.cdnurl)


def decrypt_audio_inplace(
    data: bytearray,
    keygen: PlayPlayKeygen,
    chunk_size: int = 0x2000,
    ctx_dir: str = "ctx_dumps",
) -> None:
    if keygen._playplay_ctx is None:
        raise RuntimeError("Keygen not configured")

    import os

    os.makedirs(ctx_dir, exist_ok=True)

    offset = 0
    length = len(data)
    iteration = 0

    # while offset < length:
    #     chunk = bytes(data[offset : offset + chunk_size])

    #     with open(
    #         os.path.join(
    #             ctx_dir,
    #             f"playplay_ctx_{offset:06d}.bin",
    #         ),
    #         "wb",
    #     ) as f:
    #         f.write(bytes(keygen._playplay_ctx))
    #     decrypted = keygen.decrypt_block(
    #         stream_offset=offset,
    #         data=chunk,
    #     )


    #     print(f"PlayPlayCtx block_index: {keygen._playplay_ctx.block_index}")

    #     data[offset : offset + len(decrypted)] = decrypted
    #     offset += len(decrypted)
    #     iteration += 1
    keygen.decrypt_block_2(data)


def download_and_decrypt(
    url: str,
    destination: str,
    keygen: PlayPlayKeygen,
):
    headers = {
        "user-agent": USER_AGENT,
        "range": "bytes=0-",
    }

    buffer = bytearray()

    with requests.get(url, headers=headers, stream=True) as resp:
        resp.raise_for_status()
        for chunk in resp.iter_content(chunk_size=65536):
            if chunk:
                buffer.extend(chunk)

    decrypt_audio_inplace(buffer, keygen)

    with open(destination, "wb") as f:
        f.write(buffer)


def download_track_160kbps(
    track: Track,
    resolver: StorageResolver,
    playplay: PlayPlayClient,
    keygen: PlayPlayKeygen,
):
    file_id: Optional[bytes] = None
    for audio in track.file:
        print(" format:", AudioFile.Format.Name(audio.format))
        print(" file_id:", audio.file_id.hex())
        if audio.format == TARGET_AUDIO_FORMAT:
            file_id = audio.file_id
            break

    if not file_id:
        print("  OGG 160 kbps not available")
        return

    print("selected file_id:", file_id.hex())
    obf_key = playplay.get_obfuscated_key(file_id)
    print("obfuscated_key:", obf_key.hex())
    keygen.configure(
        content_id=file_id[:16],
        obfuscated_key=obf_key,
    )
    print("derived_key:", keygen.derived_key.hex())
    urls = resolver.resolve(file_id)

    filename = f"{file_id.hex()}.ogg"
    print("  downloading:", urls[0])
    download_and_decrypt(urls[0], filename, keygen)

    print("  decrypted:", filename)


if __name__ == "__main__":
    BEARER = "BQCBBongoHy29wA5pB0MeUV8iI7QBiVRD0s230rOVBwvBJ51W7ABtnqAcWTauYTa__8SzeS9PgEGSs3dxkFLJnSuDZm7q9CoPQHCw8Bl3qsCJfeqSDPNFY0Poy7TQREVpHIiupN-JJXW5cIPEPJ64EmI2a-EW7EeLolytzw0Xl5s8PucK3LPY6Z1tCW9hrYVpdo2o3qrs-cRE3rIMzaag9O455crNlaiilXWtkCkcLAarKxR_FU-ZN5UeWsdm63VuV-GaM5aQfU6Qoe52Zd_uxaCcQORMMo5m2_Jhn1DmCjI20Ns6_T4QoH8KCM0wEAHm7rEkRVQIt1dc2MFMcfGVB7lx7A970crSFSA-5xXDxpHqcfSEpQW_LMnfakfLGSIBMY1LjxK_pgIRo5TuNvPYVM"
    EXE_PATH = "bin.exe"

    TRACK_URIS = [
        "spotify:track:7pAxY37Kl6gkqbQcbeiucE",
        # "spotify:track:51iRhxD8Ap1EubRCr9jQlR",
    ]

    keygen = PlayPlayKeygen(EXE_PATH)
    metadata = ExtendedMetadataClient(BEARER)
    resolver = StorageResolver(BEARER)
    playplay = PlayPlayClient(BEARER, keygen)

    tracks = metadata.fetch_tracks(TRACK_URIS)

    for uri, track in tracks.items():
        print(uri)
        print("  name:", track.name)
        print("  duration:", track.duration)
        print("  gid:", track.gid.hex())

        download_track_160kbps(
            track,
            resolver,
            playplay,
            keygen,
        )
        print()
