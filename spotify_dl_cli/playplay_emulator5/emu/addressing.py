from spotify_dl_cli.playplay_emulator5.consts import ANALYSIS, MEM


def align(value: int, alignment: int = MEM.PAGE_SIZE) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def rebase(load_base: int, va: int) -> int:
    return load_base + (va - ANALYSIS.BASE)
