from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class Signal(_message.Message):
    __slots__ = ("identifier", "data", "client_payload")
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    CLIENT_PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    identifier: str
    data: bytes
    client_payload: bytes
    def __init__(self, identifier: _Optional[str] = ..., data: _Optional[bytes] = ..., client_payload: _Optional[bytes] = ...) -> None: ...
