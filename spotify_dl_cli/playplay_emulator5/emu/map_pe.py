from pefile import PE
from unicorn.unicorn import Uc
from spotify_dl_cli.playplay_emulator5.emu.addressing import align


def map_pe(mu: Uc, pe: PE):
    base = getattr(pe.OPTIONAL_HEADER, "ImageBase")
    image = pe.get_memory_mapped_image()
    size = align(len(image))

    if not isinstance(image, bytes):
        raise

    mu.mem_map(base, size)
    mu.mem_write(base, image)

    return base, size
