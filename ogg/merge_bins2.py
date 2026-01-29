import os, re, argparse

def extract_number(filename: str) -> int:
    m = re.match(r"decrypt_(\d+)_", filename)
    return int(m.group(1)) if m else 10**18

def skip_spotify_custom_page_if_present(chunk: bytes) -> tuple[bytes, bool]:
    if len(chunk) >= 4 and chunk[:4] == b"OggS":
        idx = chunk.find(b"OggS", 4)
        if idx != -1:
            return chunk[idx:], True
    return chunk, False

def parse_ogg_pages_from_buffer(buf: bytearray):
    import struct
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
            # Pas une vraie page Ogg (ou données parasites) -> resync après ce point
            i = j + 4
            continue

        header_type = buf[j + 5]
        pageno = struct.unpack_from("<I", buf, j + 18)[0]  # ✅ offset correct
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

def reconstruct_ogg_from_chunks(input_dir: str, output_ogg: str):
    bin_files = [f for f in os.listdir(input_dir) if f.startswith("decrypt_") and f.endswith(".bin")]
    if not bin_files:
        raise RuntimeError(f"Aucun fichier decrypt_*.bin trouvé dans {input_dir}")
    bin_files.sort(key=extract_number)

    buf = bytearray()
    probed = False
    last_page_no = None
    pages_out = 0
    bytes_in = 0

    print(f"[start] chunks={len(bin_files)} input={input_dir}")
    print(f"[start] first={bin_files[0]}")
    print(f"[start] last ={bin_files[-1]}")
    print(f"[start] out  ={output_ogg}")

    with open(output_ogg, "wb") as fout:
        for i, filename in enumerate(bin_files, 1):
            fp = os.path.join(input_dir, filename)
            data = open(fp, "rb").read()
            if not data:
                continue
            bytes_in += len(data)

            if not probed:
                probed = True
                if data[:4] != b"OggS":
                    raise RuntimeError(
                        f"Codec non reconnu: {filename} ne commence pas par OggS "
                        f"(first16={data[:16].hex(' ')})"
                    )
                data, skipped = skip_spotify_custom_page_if_present(data)
                if skipped:
                    print(f"[info] Custom Spotify Ogg page skipped in {filename}")

            buf.extend(data)

            chunk_pages = 0
            for page_bytes, bos, pageno in parse_ogg_pages_from_buffer(buf):
                chunk_pages += 1
                pages_out += 1

                if last_page_no is None:
                    if not bos:
                        raise RuntimeError(f"Flux invalide: première page écrite non-BOS (pageno={pageno}).")
                else:
                    if pageno != last_page_no + 1:
                        raise RuntimeError(
                            f"Discontinuité: pageno={pageno}, attendu={last_page_no + 1} (sur {filename})."
                        )
                last_page_no = pageno
                fout.write(page_bytes)

            if i <= 3:
                print(f"[chunk {i}] {filename}: wrote={len(data)} pages={chunk_pages}")
            elif i % 50 == 0:
                print(f"[progress] {i}/{len(bin_files)} pages_out={pages_out}")

    out_size = os.path.getsize(output_ogg) if os.path.exists(output_ogg) else 0
    print(f"[done] bytes_in={bytes_in:,} pages_out={pages_out:,} out_size={out_size:,}")

    if pages_out == 0:
        try:
            os.remove(output_ogg)
        except OSError:
            pass
        raise RuntimeError(
            "Aucune page Ogg extraite. Causes probables:\n"
            "- Les decrypt_*.bin ne contiennent pas des pages Ogg complètes\n"
            "- La page custom n'a pas pu être skippée car le 2e 'OggS' est dans un chunk suivant\n"
            "- Chunks manquants / ordre incorrect"
        )

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    reconstruct_ogg_from_chunks(args.input, args.output)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
