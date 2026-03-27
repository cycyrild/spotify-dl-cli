BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _base62_encode(data: bytes) -> str:
    num = int.from_bytes(data, byteorder="big")

    if num == 0:
        return "0".rjust(22, "0")

    out = ""
    while num:
        num, rem = divmod(num, 62)
        out = BASE62[rem] + out

    return out.rjust(22, "0")


def track_gid_to_uri(track_gid: bytes) -> str:
    if len(track_gid) != 16:
        raise ValueError("track_gid must be exactly 16 bytes")
    return f"spotify:track:{_base62_encode(track_gid)}"
