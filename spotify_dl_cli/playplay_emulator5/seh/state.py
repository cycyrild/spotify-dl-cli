from dataclasses import dataclass
from typing import Dict, List
from spotify_dl_cli.playplay_emulator5.generated.runtimefunction_models import (
    RuntimeFunction,
)
from spotify_dl_cli.playplay_emulator5.generated.throwinfo_models import ThrowInfo
from spotify_dl_cli.playplay_emulator5.seh.registers import UnwindRegNum


@dataclass
class SehRuntimeState:
    image_base: int
    cxx_throw_exception: int
    runtime_functions: List[RuntimeFunction]
    throw_infos: Dict[int, ThrowInfo]
    runtime_function_starts: List[int]


@dataclass
class ThrownException:
    object_va: int
    throw_info_va: int
    throw_info: ThrowInfo


@dataclass
class VirtualContext:
    rip: int
    rsp: int
    regs: Dict[int, int]

    def get_reg(self, regnum: int) -> int:
        if regnum == UnwindRegNum.RSP:
            return self.rsp
        return self.regs.get(regnum, 0)

    def set_reg(self, regnum: int, value: int):
        if regnum == UnwindRegNum.RSP:
            self.rsp = value
        else:
            self.regs[regnum] = value
