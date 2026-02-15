from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class Lens(_message.Message):
    __slots__ = ("identifier",)
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    identifier: str
    def __init__(self, identifier: _Optional[str] = ...) -> None: ...

class LensState(_message.Message):
    __slots__ = ("identifier", "revision")
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    identifier: str
    revision: bytes
    def __init__(self, identifier: _Optional[str] = ..., revision: _Optional[bytes] = ...) -> None: ...
