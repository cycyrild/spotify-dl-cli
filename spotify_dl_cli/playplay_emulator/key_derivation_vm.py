import pefile
from unicorn.unicorn import Uc
from spotify_dl_cli.playplay_emulator.helpers import pack_u32

ADDR_G_PLAYPLAY_VM_WORKSPACE_POOL = 0x01BC3DE8
VM_WORKSPACE_POOL_SIZE = 68096  # 0x10A00
VM_WORKSPACE_CONST_OFFSET = 1024
VM_WORKSPACE_CONST_SIZE = 1536  # 0x600

CONST_TABLE_VA_START = 0x011BFD18
CONST_TABLE_VA_END = CONST_TABLE_VA_START + VM_WORKSPACE_CONST_SIZE


def init_playplay_vm_workspace(uc: Uc, pe: pefile.PE, vm_pool_ptr: int) -> None:
    uc.mem_write(ADDR_G_PLAYPLAY_VM_WORKSPACE_POOL, pack_u32(vm_pool_ptr))
    uc.mem_write(vm_pool_ptr, b"\x00" * VM_WORKSPACE_POOL_SIZE)
    rva_start = CONST_TABLE_VA_START - pe.OPTIONAL_HEADER.ImageBase  # type: ignore

    const_table = pe.get_data(rva_start, CONST_TABLE_VA_END - CONST_TABLE_VA_START)
    assert len(const_table) == VM_WORKSPACE_CONST_SIZE

    uc.mem_write(vm_pool_ptr + VM_WORKSPACE_CONST_OFFSET, const_table)
