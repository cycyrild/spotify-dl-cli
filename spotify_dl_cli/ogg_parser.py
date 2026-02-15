from dataclasses import dataclass
from typing import Iterable, Iterator, Optional, Tuple
import struct

"""
Incremental Ogg parser in pure Python allowing the reconstruction and structural validation of an Ogg stream from fragmented data.
"""

CAPTURE_PATTERN = b"OggS"
OGG_VERSION = 0
OGG_HEADER_FIXED_SIZE = 27

# https://en.wikipedia.org/wiki/Ogg#Page_structure
# Ogg page header layout:
# capture_pattern   4s
# version           B
# header_type       B
# granule_position  Q
# bitstream_serial  I
# page_sequence_no  I
# checksum          I
# page_segments     B
OGG_HEADER_STRUCT = struct.Struct("<4sBBQIIIB")

BOS_FLAG = 0x02


def skip_spotify_custom_page_if_present(chunk: bytes) -> tuple[bytes, bool]:
    if len(chunk) >= 4 and chunk[:4] == CAPTURE_PATTERN:
        idx = chunk.find(CAPTURE_PATTERN, 4)
        if idx != -1:
            return chunk[idx:], True
    return chunk, False


def is_bos(header_type: int) -> bool:
    return (header_type & BOS_FLAG) != 0


@dataclass(frozen=True)
class ParsedPage:
    start: int
    total_len: int
    page_bytes: bytes
    bos: bool
    pageno: int
    serial: int


def _try_parse_page_at(buf: bytearray, start: int) -> Optional[ParsedPage]:
    if len(buf) < start + OGG_HEADER_FIXED_SIZE:
        return None

    (
        capture,
        version,
        header_type,
        _granule_pos,
        serial,
        pageno,
        _checksum,
        page_segments,
    ) = OGG_HEADER_STRUCT.unpack_from(buf, start)

    if capture != CAPTURE_PATTERN:
        return None

    if version != OGG_VERSION:
        return None

    header_len = OGG_HEADER_FIXED_SIZE + page_segments
    if len(buf) < start + header_len:
        return None

    seg_start = start + OGG_HEADER_FIXED_SIZE
    seg_end = seg_start + page_segments

    body_len = sum(memoryview(buf)[seg_start:seg_end])
    total_len = header_len + body_len

    if len(buf) < start + total_len:
        return None

    page_view = memoryview(buf)[start : start + total_len]
    return ParsedPage(
        start=start,
        total_len=total_len,
        page_bytes=bytes(page_view),
        bos=is_bos(header_type),
        pageno=pageno,
        serial=serial,
    )


def parse_ogg_pages_from_buffer(
    buf: bytearray,
) -> Iterator[Tuple[bytes, bool, int, int]]:
    scan = 0
    consume_upto = 0

    while True:
        start = buf.find(CAPTURE_PATTERN, scan)
        if start == -1:
            if consume_upto > 0:
                del buf[:consume_upto]
                consume_upto = 0
            if len(buf) > 3:
                del buf[:-3]
            return

        page = _try_parse_page_at(buf, start)
        if page is None:
            if len(buf) >= start + OGG_HEADER_FIXED_SIZE:
                version = buf[start + 4]
                if version != OGG_VERSION:
                    scan = start + 1
                    continue

            if start > 0:
                del buf[:start]
            return

        yield page.page_bytes, page.bos, page.pageno, page.serial

        consume_upto = page.start + page.total_len
        scan = consume_upto

        if consume_upto > 65536 or consume_upto > (len(buf) // 2):
            del buf[:consume_upto]
            scan -= consume_upto
            consume_upto = 0


"""
Incrementally reconstruct a valid Ogg stream from fragmented audio data.

Based on the libogg streaming pattern used in:
https://github.com/Rafiuth/Soggfy/blob/master/SpotifyOggDumper/StateManager.cpp
"""


def reconstruct_ogg_from_chunks(chunks: Iterable[bytes]) -> Iterator[bytes]:
    buf = bytearray()
    probed = False
    last_page_no: int | None = None
    expected_serial: int | None = None

    for data in chunks:
        if not data:
            continue

        if not probed:
            probed = True

            if data[:4] != CAPTURE_PATTERN:
                raise RuntimeError(
                    "Unrecognized codec: first chunk does not start with OggS "
                    f"(first16={data[:16].hex(' ')})"
                )

            data, _skipped = skip_spotify_custom_page_if_present(data)

        buf.extend(data)

        for page_bytes, bos, pageno, serial in parse_ogg_pages_from_buffer(buf):
            if expected_serial is None:
                expected_serial = serial
            elif serial != expected_serial:
                raise RuntimeError(
                    f"Multiple logical streams detected: serial={serial}, expected={expected_serial}."
                )

            if last_page_no is None:
                if not bos:
                    raise RuntimeError(
                        f"Invalid stream: first page is not BOS (pageno={pageno})."
                    )
            else:
                if pageno != last_page_no + 1:
                    raise RuntimeError(
                        f"Page discontinuity: pageno={pageno}, expected={last_page_no + 1}."
                    )

            last_page_no = pageno
            yield page_bytes

    if last_page_no is None:
        raise RuntimeError("No Ogg pages extracted.")
