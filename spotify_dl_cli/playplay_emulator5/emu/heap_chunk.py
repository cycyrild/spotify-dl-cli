from unicorn.unicorn import Uc


class HeapChunk:
    def __init__(self, mu: Uc, addr: int, size: int):
        self.mu = mu
        self.addr = addr
        self.size = size

    def ptr(self) -> int:
        return self.addr

    def write(self, data: bytes) -> None:
        if len(data) != self.size:
            raise ValueError(
                f"Data size {len(data)} does not match chunk size {self.size}"
            )
        self.mu.mem_write(self.addr, data)

    def read(self) -> bytearray:
        return self.mu.mem_read(self.addr, self.size)
