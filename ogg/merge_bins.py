#!/usr/bin/env python3
r"""
Reconstitue un fichier OGG Vorbis lisible à partir de chunks decrypt_*.bin
en appliquant la logique ReceiveAudioData() via libogg (ogg_sync_*).

PowerShell:
  python .\merge_bins.py --input C:\temp\decrypt_dumps --output C:\temp\decrypt_dumps\final.ogg --libogg C:\temp\decrypt_dumps\libogg_64.dll
"""

import os
import re
import argparse
import ctypes
from ctypes import c_int, c_long, c_ubyte, c_void_p, POINTER, byref


def extract_number(filename: str) -> int:
    m = re.match(r"block_(\d+)_", filename)
    return int(m.group(1)) if m else 10**18


class ogg_sync_state(ctypes.Structure):
    _fields_ = [
        ("data", POINTER(c_ubyte)),
        ("storage", c_int),
        ("fill", c_int),
        ("returned", c_int),
        ("unsynced", c_int),
        ("headerbytes", c_int),
        ("bodybytes", c_int),
    ]


class ogg_page(ctypes.Structure):
    _fields_ = [
        ("header", POINTER(c_ubyte)),
        ("header_len", c_long),
        ("body", POINTER(c_ubyte)),
        ("body_len", c_long),
    ]


def load_libogg(dll_path: str):
    dll_path = os.path.abspath(dll_path)
    if os.path.isdir(dll_path):
        raise RuntimeError("--libogg doit pointer vers un fichier .dll, pas un dossier.")
    return ctypes.CDLL(dll_path)


def bind_ogg_functions(lib):
    lib.ogg_sync_init.argtypes = [POINTER(ogg_sync_state)]
    lib.ogg_sync_init.restype = c_int

    # IMPORTANT: ogg_sync_buffer retourne un pointeur vers un buffer binaire
    # => NE PAS utiliser c_char_p
    lib.ogg_sync_buffer.argtypes = [POINTER(ogg_sync_state), c_long]
    lib.ogg_sync_buffer.restype = c_void_p

    lib.ogg_sync_wrote.argtypes = [POINTER(ogg_sync_state), c_long]
    lib.ogg_sync_wrote.restype = c_int

    lib.ogg_sync_pageout.argtypes = [POINTER(ogg_sync_state), POINTER(ogg_page)]
    lib.ogg_sync_pageout.restype = c_int

    lib.ogg_page_bos.argtypes = [POINTER(ogg_page)]
    lib.ogg_page_bos.restype = c_int

    lib.ogg_page_eos.argtypes = [POINTER(ogg_page)]
    lib.ogg_page_eos.restype = c_int

    lib.ogg_page_pageno.argtypes = [POINTER(ogg_page)]
    lib.ogg_page_pageno.restype = c_int


def skip_spotify_custom_page_if_present(chunk: bytes) -> tuple[bytes, bool]:
    # Identique à ton C++: si chunk commence par OggS, chercher prochain OggS à partir de +4
    if len(chunk) >= 4 and chunk[:4] == b"OggS":
        idx = chunk.find(b"OggS", 4)
        if idx != -1:
            return chunk[idx:], True
    return chunk, False


def reconstruct_ogg_from_chunks(input_dir: str, output_ogg: str, libogg_path: str):
    bin_files = [
        f for f in os.listdir(input_dir)
        if f.startswith("decrypt_") and f.endswith(".bin")
    ]
    if not bin_files:
        raise RuntimeError(f"Aucun fichier decrypt_*.bin trouvé dans {input_dir}")

    bin_files.sort(key=extract_number)

    lib = load_libogg(libogg_path)
    bind_ogg_functions(lib)

    oy = ogg_sync_state()
    og = ogg_page()

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
            with open(fp, "rb") as fin:
                data = fin.read()

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

                rc = lib.ogg_sync_init(byref(oy))
                if rc != 0:
                    raise RuntimeError(f"ogg_sync_init a échoué (rc={rc})")

            # Feed libogg
            buf_ptr = lib.ogg_sync_buffer(byref(oy), len(data))
            if not buf_ptr:
                raise RuntimeError("ogg_sync_buffer a retourné NULL")

            ctypes.memmove(buf_ptr, data, len(data))
            lib.ogg_sync_wrote(byref(oy), len(data))

            chunk_pages = 0

            while lib.ogg_sync_pageout(byref(oy), byref(og)) == 1:
                chunk_pages += 1
                pages_out += 1

                bos = lib.ogg_page_bos(byref(og)) != 0
                pageno = int(lib.ogg_page_pageno(byref(og)))

                # validations ReceiveAudioData()
                if last_page_no is None:
                    if not bos:
                        raise RuntimeError(
                            f"Flux invalide: première page écrite non-BOS (pageno={pageno})."
                        )
                else:
                    if pageno != last_page_no + 1:
                        raise RuntimeError(
                            f"Discontinuité: pageno={pageno}, attendu={last_page_no + 1} (sur {filename})."
                        )

                last_page_no = pageno

                fout.write(ctypes.string_at(og.header, og.header_len))
                fout.write(ctypes.string_at(og.body, og.body_len))

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
    ap.add_argument("--libogg", required=True)
    args = ap.parse_args()

    reconstruct_ogg_from_chunks(args.input, args.output, args.libogg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
