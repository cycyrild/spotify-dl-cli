from typing import Tuple


def parse_spotify_uri(uri: str, expected_type: str | None = None) -> Tuple[str, str]:
    if not isinstance(uri, str):
        raise TypeError(f"URI must be a string, got {type(uri).__name__}")

    parts = uri.split(":")

    if len(parts) != 3:
        raise ValueError(
            f"Malformed Spotify URI (expected format spotify:type:id): {uri}"
        )

    scheme, resource_type, resource_id = parts

    if scheme != "spotify":
        raise ValueError(f"Invalid URI scheme '{scheme}', expected 'spotify'")

    if not resource_type:
        raise ValueError("Spotify URI resource type is empty")

    if not resource_id:
        raise ValueError("Spotify URI resource id is empty")

    if expected_type and resource_type != expected_type:
        raise ValueError(
            f"Invalid resource type '{resource_type}', expected '{expected_type}'"
        )

    return resource_type, resource_id
