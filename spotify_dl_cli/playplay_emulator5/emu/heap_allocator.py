from spotify_dl_cli.playplay_emulator5.emu.addressing import align
from spotify_dl_cli.playplay_emulator5.emu.heap_chunk import HeapChunk
from unicorn.unicorn import Uc


class HeapAllocator:
    DEFAULT_ALIGNMENT = 0x10

    def __init__(self, mu: Uc, base_addr: int, size: int):
        self._mu = mu
        self._base = base_addr
        self._size = size
        self._offset = 0
        self._chunks: list[HeapChunk] = []

    @classmethod
    def create(cls, mu: Uc, base_addr: int, size: int) -> "HeapAllocator":
        mu.mem_map(base_addr, align(size))
        return cls(mu, base_addr, size)

    def alloc(self, size: int) -> HeapChunk:
        aligned_offset = align(self._offset, self.DEFAULT_ALIGNMENT)

        if aligned_offset + size > self._size:
            raise MemoryError("HeapAllocator: out of memory")

        addr = self._base + aligned_offset
        self._offset = aligned_offset + size

        chunk = HeapChunk(self._mu, addr, size)
        self._chunks.append(chunk)
        return chunk

    def reset(self):
        self._offset = 0
        self._chunks.clear()

    @property
    def size(self) -> int:
        return self._size
