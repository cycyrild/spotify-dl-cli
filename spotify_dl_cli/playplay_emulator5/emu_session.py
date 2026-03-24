from spotify_dl_cli.playplay_emulator5.emu.heap_allocator import HeapAllocator
from spotify_dl_cli.playplay_emulator5.emu.heap_chunk import HeapChunk
from dataclasses import dataclass
from unicorn.unicorn import Uc


@dataclass(slots=True)
class EmuSession:
    mu: Uc
    image_base: int
    image_size: int
    heap: HeapAllocator
    vm_object_transform: int
    vm_runtime_init: int
    aes_key_va: int
    vm_obj: HeapChunk
    obfuscated_key: HeapChunk
    content_id: HeapChunk
    derived_key: HeapChunk
    captured_aes_key: bytearray | None
