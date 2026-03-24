import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from pydantic import TypeAdapter
from spotify_dl_cli.playplay_emulator5.consts import RT_FUNCTIONS
from spotify_dl_cli.playplay_emulator5.emu.addressing import rebase
from spotify_dl_cli.playplay_emulator5.generated.runtimefunction_models import (
    RuntimeFunction,
)
from spotify_dl_cli.playplay_emulator5.generated.throwinfo_models import ThrowInfo
from spotify_dl_cli.playplay_emulator5.seh.metadata import get_handler_data
from spotify_dl_cli.playplay_emulator5.seh.state import SehRuntimeState


def _load_validated_json_items(
    json_filename: Path, model_type: type[Any]
) -> Iterator[Any]:
    with json_filename.open("r") as handle:
        raw_items = json.load(handle)

    adapter = TypeAdapter(list[model_type])
    validated_items = adapter.validate_python(raw_items)

    yield from validated_items


def _load_rt_funcs_from_json(json_filename: Path) -> list[RuntimeFunction]:
    items = (
        item
        for item in _load_validated_json_items(json_filename, RuntimeFunction)
        if get_handler_data(item) is not None
    )

    return sorted(items, key=lambda rf: rf.start_rva)


def _load_throw_infos_from_json(json_filename: Path) -> dict[int, ThrowInfo]:
    return {
        item.struct_rva: item
        for item in _load_validated_json_items(json_filename, ThrowInfo)
    }


def build_state(
    image_base: int, runtime_functions_path: Path, throw_infos_path: Path
) -> SehRuntimeState:
    runtime_functions = _load_rt_funcs_from_json(runtime_functions_path)

    return SehRuntimeState(
        image_base=image_base,
        cxx_throw_exception=rebase(image_base, RT_FUNCTIONS.CXX_THROW_EXCEPTION_VA),
        runtime_functions=runtime_functions,
        throw_infos=_load_throw_infos_from_json(throw_infos_path),
        runtime_function_starts=[rf.start_rva for rf in runtime_functions],
    )
