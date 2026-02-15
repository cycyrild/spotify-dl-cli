from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class StorageResolveResponse(_message.Message):
    __slots__ = ("result", "cdnurl", "fileid")
    class Result(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        CDN: _ClassVar[StorageResolveResponse.Result]
        STORAGE: _ClassVar[StorageResolveResponse.Result]
        RESTRICTED: _ClassVar[StorageResolveResponse.Result]
    CDN: StorageResolveResponse.Result
    STORAGE: StorageResolveResponse.Result
    RESTRICTED: StorageResolveResponse.Result
    RESULT_FIELD_NUMBER: _ClassVar[int]
    CDNURL_FIELD_NUMBER: _ClassVar[int]
    FILEID_FIELD_NUMBER: _ClassVar[int]
    result: StorageResolveResponse.Result
    cdnurl: _containers.RepeatedScalarFieldContainer[str]
    fileid: bytes
    def __init__(self, result: _Optional[_Union[StorageResolveResponse.Result, str]] = ..., cdnurl: _Optional[_Iterable[str]] = ..., fileid: _Optional[bytes] = ...) -> None: ...
