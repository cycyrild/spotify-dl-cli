BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


# https://github.com/librespot-org/librespot/blob/33bf3a77ed4b549df67e8347d7d6e55b007b3ec2/core/src/spotify_id.rs#L56
def spotify_gid_to_base62(gid: bytes) -> str:
    if len(gid) != 16:
        raise ValueError("Spotify GID must be 16 bytes")

    n = int.from_bytes(gid, "big")

    dst = [0] * 22
    i = 0

    for shift in (96, 64, 32, 0):
        carry = (n >> shift) & 0xFFFFFFFF

        j = 0
        while j < i:
            carry += dst[j] << 32
            dst[j] = carry % 62
            carry //= 62
            j += 1

        while carry > 0:
            dst[i] = carry % 62
            carry //= 62
            i += 1

    return "".join(BASE62[d] for d in reversed(dst))


def track_gid_to_uri(track_gid: bytes) -> str:
    if len(track_gid) != 16:
        raise ValueError("track_gid must be exactly 16 bytes")
    return f"spotify:track:{spotify_gid_to_base62(track_gid)}"
