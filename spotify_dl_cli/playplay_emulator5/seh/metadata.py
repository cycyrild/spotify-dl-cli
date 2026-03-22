from typing import Iterator, List
from spotify_dl_cli.playplay_emulator5.generated.runtimefunction_models import (
    HandlerType4,
    IPToStateEntry4,
    RuntimeFunction,
)
from spotify_dl_cli.playplay_emulator5.generated.throwinfo_models import (
    CatchableType,
    ThrowInfo,
)


def get_handler_data(rf: RuntimeFunction):
    exc_handler = rf.unwinds.exception_handler
    if exc_handler is None or exc_handler.name != "__GSHandlerCheck_EH4":
        return None
    return exc_handler.handler_data


def get_ip_to_state_entries(rf: RuntimeFunction) -> List[IPToStateEntry4]:
    handler_data = get_handler_data(rf)
    if handler_data is None or handler_data.ip_to_state_map is None:
        return []
    return handler_data.ip_to_state_map.entries


def iter_catchable_types(throw_info: ThrowInfo) -> Iterator[CatchableType]:
    cta = throw_info.catchable_type_array
    if cta is None:
        return

    for ct in cta.catchable_types:
        if ct is not None:
            yield ct


def runtime_function_begin_va(image_base: int, rf: RuntimeFunction) -> int:
    return image_base + rf.start_rva


def runtime_function_end_va(image_base: int, rf: RuntimeFunction) -> int:
    return image_base + rf.end_rva


def catchable_type_descriptor_va(image_base: int, ct: CatchableType) -> int:
    return image_base + ct.p_type


def handler_continuation_rva(rf: RuntimeFunction, handler: HandlerType4) -> int:
    if handler.continuation_address:
        return handler.continuation_address[0]
    return rf.end_rva
