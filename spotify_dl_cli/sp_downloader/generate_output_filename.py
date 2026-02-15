import re
from typing import Any
from spotify_dl_cli.clt_extended_metadata.extendedmetadata_pb2 import Track

_INVALID_FILENAME_CHARS_RE = re.compile(r'[<>:"/\\|?*\x00-\x1F]')
_PATH_SPLIT_RE = re.compile(r"\.(?![^\[]*\])")
_ATTR_PART_RE = re.compile(r"(\w+)(\[(\d+)\])?")
_TEMPLATE_EXPR_RE = re.compile(r"\{([^}]+)\}")
_PREFIX = "track."


def slugify(value: str, replacement: str = " ") -> str:
    value = _INVALID_FILENAME_CHARS_RE.sub("", value)
    value = value.strip(" ._-")
    return value


def _resolve_attr(obj: Any, path: str) -> Any:
    current = obj

    parts = _PATH_SPLIT_RE.split(path)

    for part in parts:
        match = _ATTR_PART_RE.match(part)

        if not match:
            raise ValueError(f"Invalid template path: {path}")

        attr = match.group(1)
        index = match.group(3)

        try:
            current = getattr(current, attr)
        except AttributeError as e:
            raise ValueError(
                f"Invalid template path '{path}': object of type "
                f"'{type(current).__name__}' has no attribute '{attr}'"
            ) from e

        if index is not None:
            idx = int(index)
            try:
                current = current[idx]
            except (IndexError, TypeError) as e:
                raise ValueError(
                    f"Invalid template path '{path}': index {idx} is invalid "
                    f"for attribute '{attr}'"
                ) from e

    return current


def generate_output_filename(track: Track, template: str) -> str:
    def replacer(match: re.Match) -> str:
        expr = match.group(1)

        if not expr.startswith(_PREFIX):
            raise ValueError(f"Template expressions must start with '{_PREFIX}'")

        value = _resolve_attr(track, expr[len(_PREFIX) :])

        if not isinstance(value, str):
            value = str(value)

        return slugify(value)

    rendered = _TEMPLATE_EXPR_RE.sub(replacer, template)

    return rendered
