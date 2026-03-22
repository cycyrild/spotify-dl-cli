from unicorn.unicorn import Uc


def read_bytes(mu: Uc, va: int, size: int) -> bytes:
    return bytes(mu.mem_read(va, size))


def read_u32(mu: Uc, va: int) -> int:
    return int.from_bytes(read_bytes(mu, va, 4), "little", signed=False)


def read_u64(mu: Uc, va: int) -> int:
    return int.from_bytes(read_bytes(mu, va, 8), "little", signed=False)


def write_bytes(mu: Uc, va: int, data: bytes):
    mu.mem_write(va, data)


def write_u32(mu: Uc, va: int, value: int):
    mu.mem_write(va, value.to_bytes(4, "little", signed=False))


def write_u64(mu: Uc, va: int, value: int):
    mu.mem_write(va, value.to_bytes(8, "little", signed=False))
