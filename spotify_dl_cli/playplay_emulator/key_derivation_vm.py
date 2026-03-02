import pefile
from unicorn.unicorn import Uc
from .helpers import pack_u32
from .constants import PLAYPLAY_VM as VM


def init_playplay_vm_workspace(uc: Uc, pe: pefile.PE, vm_pool_ptr: int) -> None:
    uc.mem_write(VM.ADDR_G_WORKSPACE_POOL, pack_u32(vm_pool_ptr))
    uc.mem_write(vm_pool_ptr, b"\x00" * VM.WORKSPACE_POOL_SIZE)
    rva_start = VM.CONST_TABLE_VA_START - pe.OPTIONAL_HEADER.ImageBase  # type: ignore

    const_table = pe.get_data(
        rva_start, VM.CONST_TABLE_VA_END - VM.CONST_TABLE_VA_START
    )
    assert len(const_table) == VM.WORKSPACE_CONST_SIZE

    uc.mem_write(vm_pool_ptr + VM.WORKSPACE_CONST_OFFSET, const_table)
