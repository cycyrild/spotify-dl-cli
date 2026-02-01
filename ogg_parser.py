from typing import Iterable, Iterator, Tuple
import re
import struct


def skip_spotify_custom_page_if_present(chunk: bytes) -> tuple[bytes, bool]:
    if len(chunk) >= 4 and chunk[:4] == b"OggS":
        idx = chunk.find(b"OggS", 4)
        if idx != -1:
            return chunk[idx:], True
    return chunk, False


def parse_ogg_pages_from_buffer(
    buf: bytearray,
) -> Iterator[Tuple[bytes, bool, int]]:
    i = 0

    while True:
        j = buf.find(b"OggS", i)
        if j == -1:
            if len(buf) > 3:
                del buf[:-3]
            return

        if len(buf) < j + 27:
            if j > 0:
                del buf[:j]
            return

        version = buf[j + 4]
        if version != 0:
            i = j + 4
            continue

        header_type = buf[j + 5]
        pageno = struct.unpack_from("<I", buf, j + 18)[0]
        page_segments = buf[j + 26]

        header_len = 27 + page_segments
        if len(buf) < j + header_len:
            if j > 0:
                del buf[:j]
            return

        seg_table = buf[j + 27 : j + 27 + page_segments]
        body_len = sum(seg_table)
        total_len = header_len + body_len

        if len(buf) < j + total_len:
            if j > 0:
                del buf[:j]
            return

        page = bytes(buf[j : j + total_len])
        is_bos = (header_type & 0x02) != 0

        del buf[: j + total_len]
        i = 0

        yield page, is_bos, pageno


def reconstruct_ogg_from_chunks(
    chunks: Iterable[bytes],
) -> Iterator[bytes]:
    buf = bytearray()
    probed = False
    last_page_no: int | None = None

    for chunk_index, data in enumerate(chunks):
        if not data:
            continue

        if not probed:
            probed = True

            if data[:4] != b"OggS":
                raise RuntimeError(
                    "Unrecognized codec: first chunk does not start with OggS "
                    f"(first16={data[:16].hex(' ')})"
                )

            data, skipped = skip_spotify_custom_page_if_present(data)

        buf.extend(data)

        for page_bytes, bos, pageno in parse_ogg_pages_from_buffer(buf):
            if last_page_no is None:
                if not bos:
                    raise RuntimeError(
                        f"Invalid stream: first page is not BOS (pageno={pageno})."
                    )
            else:
                if pageno != last_page_no + 1:
                    raise RuntimeError(
                        f"Page discontinuity: pageno={pageno}, "
                        f"expected={last_page_no + 1}."
                    )

            last_page_no = pageno
            yield page_bytes

    if last_page_no is None:
        raise RuntimeError(
            "No Ogg pages extracted. Possible causes:\n"
            "- Chunks do not contain complete Ogg pages\n"
            "- Spotify custom page spans multiple chunks\n"
            "- Missing or misordered chunks"
        )
