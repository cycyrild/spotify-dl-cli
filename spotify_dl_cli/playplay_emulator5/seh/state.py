from dataclasses import dataclass
from spotify_dl_cli.playplay_emulator5.generated.runtimefunction_models import (
    RuntimeFunction,
)
from spotify_dl_cli.playplay_emulator5.generated.throwinfo_models import ThrowInfo
from spotify_dl_cli.playplay_emulator5.seh.registers import UnwindRegNum


@dataclass(slots=True, frozen=True)
class SehRuntimeState:
    image_base: int
    cxx_throw_exception: int
    runtime_functions: list[RuntimeFunction]
    throw_infos: dict[int, ThrowInfo]
    runtime_function_starts: list[int]


@dataclass(slots=True, frozen=True)
class ThrownException:
    object_va: int
    throw_info_va: int
    throw_info: ThrowInfo


@dataclass(slots=True)
class VirtualContext:
    rip: int
    rsp: int
    regs: dict[int, int]

    def get_reg(self, regnum: int) -> int:
        if regnum == UnwindRegNum.RSP:
            return self.rsp
        return self.regs.get(regnum, 0)

    def set_reg(self, regnum: int, value: int):
        if regnum == UnwindRegNum.RSP:
            self.rsp = value
        else:
            self.regs[regnum] = value
