from spotify_dl_cli.playplay_emulator5.emu.addressing import align
from spotify_dl_cli.playplay_emulator5.emu.heap_chunk import HeapChunk
from unicorn.unicorn import Uc


class HeapAllocator:
    DEFAULT_ALIGNMENT = 0x10

    def __init__(self, mu: Uc, base_addr: int, size: int):
        self.mu = mu
        self.base = base_addr
        self.size = size
        self.offset = 0
        self.chunks: list[HeapChunk] = []

    @classmethod
    def create(cls, mu: Uc, base_addr: int, size: int):
        mu.mem_map(base_addr, align(size))
        return cls(mu, base_addr, size)

    def alloc(self, size: int) -> HeapChunk:
        aligned_offset = align(self.offset, self.DEFAULT_ALIGNMENT)

        if aligned_offset + size > self.size:
            raise MemoryError("HeapAllocator: out of memory")

        addr = self.base + aligned_offset
        self.offset = aligned_offset + size

        chunk = HeapChunk(self.mu, addr, size)
        self.chunks.append(chunk)
        return chunk

    def reset(self):
        self.offset = 0
        self.chunks.clear()
