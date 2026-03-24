from unicorn.unicorn import Uc


class HeapChunk:
    def __init__(self, mu: Uc, addr: int, size: int):
        self._mu = mu
        self._addr = addr
        self._size = size

    @property
    def ptr(self) -> int:
        return self._addr

    @property
    def size(self) -> int:
        return self._size

    def write(self, data: bytes) -> None:
        if len(data) != self._size:
            raise ValueError(
                f"Data size {len(data)} does not match chunk size {self._size}"
            )
        self._mu.mem_write(self._addr, data)

    def read(self) -> bytearray:
        return self._mu.mem_read(self._addr, self._size)
