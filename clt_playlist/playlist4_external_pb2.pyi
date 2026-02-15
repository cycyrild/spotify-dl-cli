from clt_playlist import lens_model_pb2 as _lens_model_pb2
from clt_playlist import playlist_permission_pb2 as _playlist_permission_pb2
from clt_playlist import signal_model_pb2 as _signal_model_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ListAttributeKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    LIST_UNKNOWN: _ClassVar[ListAttributeKind]
    LIST_NAME: _ClassVar[ListAttributeKind]
    LIST_DESCRIPTION: _ClassVar[ListAttributeKind]
    LIST_PICTURE: _ClassVar[ListAttributeKind]
    LIST_COLLABORATIVE: _ClassVar[ListAttributeKind]
    LIST_PL3_VERSION: _ClassVar[ListAttributeKind]
    LIST_DELETED_BY_OWNER: _ClassVar[ListAttributeKind]
    LIST_CLIENT_ID: _ClassVar[ListAttributeKind]
    LIST_FORMAT: _ClassVar[ListAttributeKind]
    LIST_FORMAT_ATTRIBUTES: _ClassVar[ListAttributeKind]
    LIST_PICTURE_SIZE: _ClassVar[ListAttributeKind]
    LIST_SEQUENCE_CONTEXT_TEMPLATE: _ClassVar[ListAttributeKind]
    LIST_AI_CURATION_REFERENCE_ID: _ClassVar[ListAttributeKind]

class ItemAttributeKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ITEM_UNKNOWN: _ClassVar[ItemAttributeKind]
    ITEM_ADDED_BY: _ClassVar[ItemAttributeKind]
    ITEM_TIMESTAMP: _ClassVar[ItemAttributeKind]
    ITEM_SEEN_AT: _ClassVar[ItemAttributeKind]
    ITEM_PUBLIC: _ClassVar[ItemAttributeKind]
    ITEM_FORMAT_ATTRIBUTES: _ClassVar[ItemAttributeKind]
    ITEM_ID: _ClassVar[ItemAttributeKind]
    ITEM_SOURCE_LENS: _ClassVar[ItemAttributeKind]
    ITEM_AVAILABLE_SIGNALS: _ClassVar[ItemAttributeKind]
    ITEM_RECOMMENDATION_INFO: _ClassVar[ItemAttributeKind]
    ITEM_SEQUENCE_CHILD_TEMPLATE: _ClassVar[ItemAttributeKind]

class GeoblockBlockingType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GEOBLOCK_BLOCKING_TYPE_UNSPECIFIED: _ClassVar[GeoblockBlockingType]
    GEOBLOCK_BLOCKING_TYPE_TITLE: _ClassVar[GeoblockBlockingType]
    GEOBLOCK_BLOCKING_TYPE_DESCRIPTION: _ClassVar[GeoblockBlockingType]
    GEOBLOCK_BLOCKING_TYPE_IMAGE: _ClassVar[GeoblockBlockingType]
LIST_UNKNOWN: ListAttributeKind
LIST_NAME: ListAttributeKind
LIST_DESCRIPTION: ListAttributeKind
LIST_PICTURE: ListAttributeKind
LIST_COLLABORATIVE: ListAttributeKind
LIST_PL3_VERSION: ListAttributeKind
LIST_DELETED_BY_OWNER: ListAttributeKind
LIST_CLIENT_ID: ListAttributeKind
LIST_FORMAT: ListAttributeKind
LIST_FORMAT_ATTRIBUTES: ListAttributeKind
LIST_PICTURE_SIZE: ListAttributeKind
LIST_SEQUENCE_CONTEXT_TEMPLATE: ListAttributeKind
LIST_AI_CURATION_REFERENCE_ID: ListAttributeKind
ITEM_UNKNOWN: ItemAttributeKind
ITEM_ADDED_BY: ItemAttributeKind
ITEM_TIMESTAMP: ItemAttributeKind
ITEM_SEEN_AT: ItemAttributeKind
ITEM_PUBLIC: ItemAttributeKind
ITEM_FORMAT_ATTRIBUTES: ItemAttributeKind
ITEM_ID: ItemAttributeKind
ITEM_SOURCE_LENS: ItemAttributeKind
ITEM_AVAILABLE_SIGNALS: ItemAttributeKind
ITEM_RECOMMENDATION_INFO: ItemAttributeKind
ITEM_SEQUENCE_CHILD_TEMPLATE: ItemAttributeKind
GEOBLOCK_BLOCKING_TYPE_UNSPECIFIED: GeoblockBlockingType
GEOBLOCK_BLOCKING_TYPE_TITLE: GeoblockBlockingType
GEOBLOCK_BLOCKING_TYPE_DESCRIPTION: GeoblockBlockingType
GEOBLOCK_BLOCKING_TYPE_IMAGE: GeoblockBlockingType

class Item(_message.Message):
    __slots__ = ("uri", "attributes")
    URI_FIELD_NUMBER: _ClassVar[int]
    ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    uri: str
    attributes: ItemAttributes
    def __init__(self, uri: _Optional[str] = ..., attributes: _Optional[_Union[ItemAttributes, _Mapping]] = ...) -> None: ...

class MetaItem(_message.Message):
    __slots__ = ("revision", "attributes", "length", "timestamp", "owner_username", "abuse_reporting_enabled", "capabilities", "geoblock", "status_code")
    REVISION_FIELD_NUMBER: _ClassVar[int]
    ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    OWNER_USERNAME_FIELD_NUMBER: _ClassVar[int]
    ABUSE_REPORTING_ENABLED_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    GEOBLOCK_FIELD_NUMBER: _ClassVar[int]
    STATUS_CODE_FIELD_NUMBER: _ClassVar[int]
    revision: bytes
    attributes: ListAttributes
    length: int
    timestamp: int
    owner_username: str
    abuse_reporting_enabled: bool
    capabilities: _playlist_permission_pb2.Capabilities
    geoblock: _containers.RepeatedScalarFieldContainer[GeoblockBlockingType]
    status_code: int
    def __init__(self, revision: _Optional[bytes] = ..., attributes: _Optional[_Union[ListAttributes, _Mapping]] = ..., length: _Optional[int] = ..., timestamp: _Optional[int] = ..., owner_username: _Optional[str] = ..., abuse_reporting_enabled: _Optional[bool] = ..., capabilities: _Optional[_Union[_playlist_permission_pb2.Capabilities, _Mapping]] = ..., geoblock: _Optional[_Iterable[_Union[GeoblockBlockingType, str]]] = ..., status_code: _Optional[int] = ...) -> None: ...

class ListItems(_message.Message):
    __slots__ = ("pos", "truncated", "items", "meta_items", "available_signals", "continuation_token")
    POS_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    META_ITEMS_FIELD_NUMBER: _ClassVar[int]
    AVAILABLE_SIGNALS_FIELD_NUMBER: _ClassVar[int]
    CONTINUATION_TOKEN_FIELD_NUMBER: _ClassVar[int]
    pos: int
    truncated: bool
    items: _containers.RepeatedCompositeFieldContainer[Item]
    meta_items: _containers.RepeatedCompositeFieldContainer[MetaItem]
    available_signals: _containers.RepeatedCompositeFieldContainer[_signal_model_pb2.Signal]
    continuation_token: str
    def __init__(self, pos: _Optional[int] = ..., truncated: _Optional[bool] = ..., items: _Optional[_Iterable[_Union[Item, _Mapping]]] = ..., meta_items: _Optional[_Iterable[_Union[MetaItem, _Mapping]]] = ..., available_signals: _Optional[_Iterable[_Union[_signal_model_pb2.Signal, _Mapping]]] = ..., continuation_token: _Optional[str] = ...) -> None: ...

class PaginatedUnfollowedListItems(_message.Message):
    __slots__ = ("limit", "offset", "nextPageIndex", "previousPageIndex", "totalPages", "items")
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    NEXTPAGEINDEX_FIELD_NUMBER: _ClassVar[int]
    PREVIOUSPAGEINDEX_FIELD_NUMBER: _ClassVar[int]
    TOTALPAGES_FIELD_NUMBER: _ClassVar[int]
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    limit: int
    offset: int
    nextPageIndex: int
    previousPageIndex: int
    totalPages: int
    items: _containers.RepeatedCompositeFieldContainer[UnfollowedListItem]
    def __init__(self, limit: _Optional[int] = ..., offset: _Optional[int] = ..., nextPageIndex: _Optional[int] = ..., previousPageIndex: _Optional[int] = ..., totalPages: _Optional[int] = ..., items: _Optional[_Iterable[_Union[UnfollowedListItem, _Mapping]]] = ...) -> None: ...

class UnfollowedListItem(_message.Message):
    __slots__ = ("uri", "recoverable", "name", "deleted_at", "length")
    URI_FIELD_NUMBER: _ClassVar[int]
    RECOVERABLE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    DELETED_AT_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    uri: str
    recoverable: bool
    name: str
    deleted_at: int
    length: int
    def __init__(self, uri: _Optional[str] = ..., recoverable: _Optional[bool] = ..., name: _Optional[str] = ..., deleted_at: _Optional[int] = ..., length: _Optional[int] = ...) -> None: ...

class FormatListAttribute(_message.Message):
    __slots__ = ("key", "value")
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    key: str
    value: str
    def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...

class PictureSize(_message.Message):
    __slots__ = ("target_name", "url")
    TARGET_NAME_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    target_name: str
    url: str
    def __init__(self, target_name: _Optional[str] = ..., url: _Optional[str] = ...) -> None: ...

class RecommendationInfo(_message.Message):
    __slots__ = ("is_recommendation",)
    IS_RECOMMENDATION_FIELD_NUMBER: _ClassVar[int]
    is_recommendation: bool
    def __init__(self, is_recommendation: _Optional[bool] = ...) -> None: ...

class ListAttributes(_message.Message):
    __slots__ = ("name", "description", "picture", "collaborative", "pl3_version", "deleted_by_owner", "client_id", "format", "format_attributes", "picture_size", "sequence_context_template", "ai_curation_reference_id")
    NAME_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    PICTURE_FIELD_NUMBER: _ClassVar[int]
    COLLABORATIVE_FIELD_NUMBER: _ClassVar[int]
    PL3_VERSION_FIELD_NUMBER: _ClassVar[int]
    DELETED_BY_OWNER_FIELD_NUMBER: _ClassVar[int]
    CLIENT_ID_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    FORMAT_ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    PICTURE_SIZE_FIELD_NUMBER: _ClassVar[int]
    SEQUENCE_CONTEXT_TEMPLATE_FIELD_NUMBER: _ClassVar[int]
    AI_CURATION_REFERENCE_ID_FIELD_NUMBER: _ClassVar[int]
    name: str
    description: str
    picture: bytes
    collaborative: bool
    pl3_version: str
    deleted_by_owner: bool
    client_id: str
    format: str
    format_attributes: _containers.RepeatedCompositeFieldContainer[FormatListAttribute]
    picture_size: _containers.RepeatedCompositeFieldContainer[PictureSize]
    sequence_context_template: bytes
    ai_curation_reference_id: bytes
    def __init__(self, name: _Optional[str] = ..., description: _Optional[str] = ..., picture: _Optional[bytes] = ..., collaborative: _Optional[bool] = ..., pl3_version: _Optional[str] = ..., deleted_by_owner: _Optional[bool] = ..., client_id: _Optional[str] = ..., format: _Optional[str] = ..., format_attributes: _Optional[_Iterable[_Union[FormatListAttribute, _Mapping]]] = ..., picture_size: _Optional[_Iterable[_Union[PictureSize, _Mapping]]] = ..., sequence_context_template: _Optional[bytes] = ..., ai_curation_reference_id: _Optional[bytes] = ...) -> None: ...

class ItemAttributes(_message.Message):
    __slots__ = ("added_by", "timestamp", "seen_at", "public", "format_attributes", "item_id", "source_lens", "available_signals", "recommendation_info", "sequence_child_template")
    ADDED_BY_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    SEEN_AT_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_FIELD_NUMBER: _ClassVar[int]
    FORMAT_ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    ITEM_ID_FIELD_NUMBER: _ClassVar[int]
    SOURCE_LENS_FIELD_NUMBER: _ClassVar[int]
    AVAILABLE_SIGNALS_FIELD_NUMBER: _ClassVar[int]
    RECOMMENDATION_INFO_FIELD_NUMBER: _ClassVar[int]
    SEQUENCE_CHILD_TEMPLATE_FIELD_NUMBER: _ClassVar[int]
    added_by: str
    timestamp: int
    seen_at: int
    public: bool
    format_attributes: _containers.RepeatedCompositeFieldContainer[FormatListAttribute]
    item_id: bytes
    source_lens: _lens_model_pb2.Lens
    available_signals: _containers.RepeatedCompositeFieldContainer[_signal_model_pb2.Signal]
    recommendation_info: RecommendationInfo
    sequence_child_template: bytes
    def __init__(self, added_by: _Optional[str] = ..., timestamp: _Optional[int] = ..., seen_at: _Optional[int] = ..., public: _Optional[bool] = ..., format_attributes: _Optional[_Iterable[_Union[FormatListAttribute, _Mapping]]] = ..., item_id: _Optional[bytes] = ..., source_lens: _Optional[_Union[_lens_model_pb2.Lens, _Mapping]] = ..., available_signals: _Optional[_Iterable[_Union[_signal_model_pb2.Signal, _Mapping]]] = ..., recommendation_info: _Optional[_Union[RecommendationInfo, _Mapping]] = ..., sequence_child_template: _Optional[bytes] = ...) -> None: ...

class Add(_message.Message):
    __slots__ = ("from_index", "items", "add_last", "add_first", "add_before_item", "add_after_item")
    FROM_INDEX_FIELD_NUMBER: _ClassVar[int]
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    ADD_LAST_FIELD_NUMBER: _ClassVar[int]
    ADD_FIRST_FIELD_NUMBER: _ClassVar[int]
    ADD_BEFORE_ITEM_FIELD_NUMBER: _ClassVar[int]
    ADD_AFTER_ITEM_FIELD_NUMBER: _ClassVar[int]
    from_index: int
    items: _containers.RepeatedCompositeFieldContainer[Item]
    add_last: bool
    add_first: bool
    add_before_item: Item
    add_after_item: Item
    def __init__(self, from_index: _Optional[int] = ..., items: _Optional[_Iterable[_Union[Item, _Mapping]]] = ..., add_last: _Optional[bool] = ..., add_first: _Optional[bool] = ..., add_before_item: _Optional[_Union[Item, _Mapping]] = ..., add_after_item: _Optional[_Union[Item, _Mapping]] = ...) -> None: ...

class Rem(_message.Message):
    __slots__ = ("from_index", "length", "items", "items_as_key")
    FROM_INDEX_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    ITEMS_AS_KEY_FIELD_NUMBER: _ClassVar[int]
    from_index: int
    length: int
    items: _containers.RepeatedCompositeFieldContainer[Item]
    items_as_key: bool
    def __init__(self, from_index: _Optional[int] = ..., length: _Optional[int] = ..., items: _Optional[_Iterable[_Union[Item, _Mapping]]] = ..., items_as_key: _Optional[bool] = ...) -> None: ...

class Mov(_message.Message):
    __slots__ = ("from_index", "length", "to_index", "items", "add_before_item", "add_after_item", "add_first", "add_last")
    FROM_INDEX_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    TO_INDEX_FIELD_NUMBER: _ClassVar[int]
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    ADD_BEFORE_ITEM_FIELD_NUMBER: _ClassVar[int]
    ADD_AFTER_ITEM_FIELD_NUMBER: _ClassVar[int]
    ADD_FIRST_FIELD_NUMBER: _ClassVar[int]
    ADD_LAST_FIELD_NUMBER: _ClassVar[int]
    from_index: int
    length: int
    to_index: int
    items: _containers.RepeatedCompositeFieldContainer[Item]
    add_before_item: Item
    add_after_item: Item
    add_first: bool
    add_last: bool
    def __init__(self, from_index: _Optional[int] = ..., length: _Optional[int] = ..., to_index: _Optional[int] = ..., items: _Optional[_Iterable[_Union[Item, _Mapping]]] = ..., add_before_item: _Optional[_Union[Item, _Mapping]] = ..., add_after_item: _Optional[_Union[Item, _Mapping]] = ..., add_first: _Optional[bool] = ..., add_last: _Optional[bool] = ...) -> None: ...

class ItemAttributesPartialState(_message.Message):
    __slots__ = ("values", "no_value")
    VALUES_FIELD_NUMBER: _ClassVar[int]
    NO_VALUE_FIELD_NUMBER: _ClassVar[int]
    values: ItemAttributes
    no_value: _containers.RepeatedScalarFieldContainer[ItemAttributeKind]
    def __init__(self, values: _Optional[_Union[ItemAttributes, _Mapping]] = ..., no_value: _Optional[_Iterable[_Union[ItemAttributeKind, str]]] = ...) -> None: ...

class ListAttributesPartialState(_message.Message):
    __slots__ = ("values", "no_value")
    VALUES_FIELD_NUMBER: _ClassVar[int]
    NO_VALUE_FIELD_NUMBER: _ClassVar[int]
    values: ListAttributes
    no_value: _containers.RepeatedScalarFieldContainer[ListAttributeKind]
    def __init__(self, values: _Optional[_Union[ListAttributes, _Mapping]] = ..., no_value: _Optional[_Iterable[_Union[ListAttributeKind, str]]] = ...) -> None: ...

class UpdateItemAttributes(_message.Message):
    __slots__ = ("index", "new_attributes", "old_attributes", "item")
    INDEX_FIELD_NUMBER: _ClassVar[int]
    NEW_ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    OLD_ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    ITEM_FIELD_NUMBER: _ClassVar[int]
    index: int
    new_attributes: ItemAttributesPartialState
    old_attributes: ItemAttributesPartialState
    item: Item
    def __init__(self, index: _Optional[int] = ..., new_attributes: _Optional[_Union[ItemAttributesPartialState, _Mapping]] = ..., old_attributes: _Optional[_Union[ItemAttributesPartialState, _Mapping]] = ..., item: _Optional[_Union[Item, _Mapping]] = ...) -> None: ...

class UpdateListAttributes(_message.Message):
    __slots__ = ("new_attributes", "old_attributes")
    NEW_ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    OLD_ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    new_attributes: ListAttributesPartialState
    old_attributes: ListAttributesPartialState
    def __init__(self, new_attributes: _Optional[_Union[ListAttributesPartialState, _Mapping]] = ..., old_attributes: _Optional[_Union[ListAttributesPartialState, _Mapping]] = ...) -> None: ...

class UpdateItemUris(_message.Message):
    __slots__ = ("uri_replacements",)
    URI_REPLACEMENTS_FIELD_NUMBER: _ClassVar[int]
    uri_replacements: _containers.RepeatedCompositeFieldContainer[UriReplacement]
    def __init__(self, uri_replacements: _Optional[_Iterable[_Union[UriReplacement, _Mapping]]] = ...) -> None: ...

class UriReplacement(_message.Message):
    __slots__ = ("index", "item", "new_uri")
    INDEX_FIELD_NUMBER: _ClassVar[int]
    ITEM_FIELD_NUMBER: _ClassVar[int]
    NEW_URI_FIELD_NUMBER: _ClassVar[int]
    index: int
    item: Item
    new_uri: str
    def __init__(self, index: _Optional[int] = ..., item: _Optional[_Union[Item, _Mapping]] = ..., new_uri: _Optional[str] = ...) -> None: ...

class Op(_message.Message):
    __slots__ = ("kind", "add", "rem", "mov", "update_item_attributes", "update_list_attributes", "update_item_uris")
    class Kind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        KIND_UNKNOWN: _ClassVar[Op.Kind]
        ADD: _ClassVar[Op.Kind]
        REM: _ClassVar[Op.Kind]
        MOV: _ClassVar[Op.Kind]
        UPDATE_ITEM_ATTRIBUTES: _ClassVar[Op.Kind]
        UPDATE_LIST_ATTRIBUTES: _ClassVar[Op.Kind]
        UPDATE_ITEM_URIS: _ClassVar[Op.Kind]
    KIND_UNKNOWN: Op.Kind
    ADD: Op.Kind
    REM: Op.Kind
    MOV: Op.Kind
    UPDATE_ITEM_ATTRIBUTES: Op.Kind
    UPDATE_LIST_ATTRIBUTES: Op.Kind
    UPDATE_ITEM_URIS: Op.Kind
    KIND_FIELD_NUMBER: _ClassVar[int]
    ADD_FIELD_NUMBER: _ClassVar[int]
    REM_FIELD_NUMBER: _ClassVar[int]
    MOV_FIELD_NUMBER: _ClassVar[int]
    UPDATE_ITEM_ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    UPDATE_LIST_ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    UPDATE_ITEM_URIS_FIELD_NUMBER: _ClassVar[int]
    kind: Op.Kind
    add: Add
    rem: Rem
    mov: Mov
    update_item_attributes: UpdateItemAttributes
    update_list_attributes: UpdateListAttributes
    update_item_uris: UpdateItemUris
    def __init__(self, kind: _Optional[_Union[Op.Kind, str]] = ..., add: _Optional[_Union[Add, _Mapping]] = ..., rem: _Optional[_Union[Rem, _Mapping]] = ..., mov: _Optional[_Union[Mov, _Mapping]] = ..., update_item_attributes: _Optional[_Union[UpdateItemAttributes, _Mapping]] = ..., update_list_attributes: _Optional[_Union[UpdateListAttributes, _Mapping]] = ..., update_item_uris: _Optional[_Union[UpdateItemUris, _Mapping]] = ...) -> None: ...

class OpList(_message.Message):
    __slots__ = ("ops",)
    OPS_FIELD_NUMBER: _ClassVar[int]
    ops: _containers.RepeatedCompositeFieldContainer[Op]
    def __init__(self, ops: _Optional[_Iterable[_Union[Op, _Mapping]]] = ...) -> None: ...

class ChangeInfo(_message.Message):
    __slots__ = ("user", "timestamp", "admin", "undo", "redo", "merge", "compressed", "migration", "split_id", "source")
    USER_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    ADMIN_FIELD_NUMBER: _ClassVar[int]
    UNDO_FIELD_NUMBER: _ClassVar[int]
    REDO_FIELD_NUMBER: _ClassVar[int]
    MERGE_FIELD_NUMBER: _ClassVar[int]
    COMPRESSED_FIELD_NUMBER: _ClassVar[int]
    MIGRATION_FIELD_NUMBER: _ClassVar[int]
    SPLIT_ID_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    user: str
    timestamp: int
    admin: bool
    undo: bool
    redo: bool
    merge: bool
    compressed: bool
    migration: bool
    split_id: int
    source: SourceInfo
    def __init__(self, user: _Optional[str] = ..., timestamp: _Optional[int] = ..., admin: _Optional[bool] = ..., undo: _Optional[bool] = ..., redo: _Optional[bool] = ..., merge: _Optional[bool] = ..., compressed: _Optional[bool] = ..., migration: _Optional[bool] = ..., split_id: _Optional[int] = ..., source: _Optional[_Union[SourceInfo, _Mapping]] = ...) -> None: ...

class SourceInfo(_message.Message):
    __slots__ = ("client", "app", "source", "version", "server_domain")
    class Client(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        CLIENT_UNKNOWN: _ClassVar[SourceInfo.Client]
        NATIVE_HERMES: _ClassVar[SourceInfo.Client]
        CLIENT: _ClassVar[SourceInfo.Client]
        PYTHON: _ClassVar[SourceInfo.Client]
        JAVA: _ClassVar[SourceInfo.Client]
        WEBPLAYER: _ClassVar[SourceInfo.Client]
        LIBSPOTIFY: _ClassVar[SourceInfo.Client]
    CLIENT_UNKNOWN: SourceInfo.Client
    NATIVE_HERMES: SourceInfo.Client
    CLIENT: SourceInfo.Client
    PYTHON: SourceInfo.Client
    JAVA: SourceInfo.Client
    WEBPLAYER: SourceInfo.Client
    LIBSPOTIFY: SourceInfo.Client
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    APP_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    SERVER_DOMAIN_FIELD_NUMBER: _ClassVar[int]
    client: SourceInfo.Client
    app: str
    source: str
    version: str
    server_domain: str
    def __init__(self, client: _Optional[_Union[SourceInfo.Client, str]] = ..., app: _Optional[str] = ..., source: _Optional[str] = ..., version: _Optional[str] = ..., server_domain: _Optional[str] = ...) -> None: ...

class Delta(_message.Message):
    __slots__ = ("base_version", "ops", "info")
    BASE_VERSION_FIELD_NUMBER: _ClassVar[int]
    OPS_FIELD_NUMBER: _ClassVar[int]
    INFO_FIELD_NUMBER: _ClassVar[int]
    base_version: bytes
    ops: _containers.RepeatedCompositeFieldContainer[Op]
    info: ChangeInfo
    def __init__(self, base_version: _Optional[bytes] = ..., ops: _Optional[_Iterable[_Union[Op, _Mapping]]] = ..., info: _Optional[_Union[ChangeInfo, _Mapping]] = ...) -> None: ...

class Diff(_message.Message):
    __slots__ = ("from_revision", "ops", "to_revision")
    FROM_REVISION_FIELD_NUMBER: _ClassVar[int]
    OPS_FIELD_NUMBER: _ClassVar[int]
    TO_REVISION_FIELD_NUMBER: _ClassVar[int]
    from_revision: bytes
    ops: _containers.RepeatedCompositeFieldContainer[Op]
    to_revision: bytes
    def __init__(self, from_revision: _Optional[bytes] = ..., ops: _Optional[_Iterable[_Union[Op, _Mapping]]] = ..., to_revision: _Optional[bytes] = ...) -> None: ...

class ListChanges(_message.Message):
    __slots__ = ("base_revision", "deltas", "want_resulting_revisions", "want_sync_result", "nonces")
    BASE_REVISION_FIELD_NUMBER: _ClassVar[int]
    DELTAS_FIELD_NUMBER: _ClassVar[int]
    WANT_RESULTING_REVISIONS_FIELD_NUMBER: _ClassVar[int]
    WANT_SYNC_RESULT_FIELD_NUMBER: _ClassVar[int]
    NONCES_FIELD_NUMBER: _ClassVar[int]
    base_revision: bytes
    deltas: _containers.RepeatedCompositeFieldContainer[Delta]
    want_resulting_revisions: bool
    want_sync_result: bool
    nonces: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, base_revision: _Optional[bytes] = ..., deltas: _Optional[_Iterable[_Union[Delta, _Mapping]]] = ..., want_resulting_revisions: _Optional[bool] = ..., want_sync_result: _Optional[bool] = ..., nonces: _Optional[_Iterable[int]] = ...) -> None: ...

class ListSignals(_message.Message):
    __slots__ = ("base_revision", "emitted_signals")
    BASE_REVISION_FIELD_NUMBER: _ClassVar[int]
    EMITTED_SIGNALS_FIELD_NUMBER: _ClassVar[int]
    base_revision: bytes
    emitted_signals: _containers.RepeatedCompositeFieldContainer[_signal_model_pb2.Signal]
    def __init__(self, base_revision: _Optional[bytes] = ..., emitted_signals: _Optional[_Iterable[_Union[_signal_model_pb2.Signal, _Mapping]]] = ...) -> None: ...

class SelectedListContent(_message.Message):
    __slots__ = ("revision", "length", "attributes", "contents", "diff", "sync_result", "resulting_revisions", "multiple_heads", "up_to_date", "nonces", "timestamp", "owner_username", "abuse_reporting_enabled", "capabilities", "geoblock", "changes_require_resync", "created_at", "applied_lenses")
    REVISION_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    CONTENTS_FIELD_NUMBER: _ClassVar[int]
    DIFF_FIELD_NUMBER: _ClassVar[int]
    SYNC_RESULT_FIELD_NUMBER: _ClassVar[int]
    RESULTING_REVISIONS_FIELD_NUMBER: _ClassVar[int]
    MULTIPLE_HEADS_FIELD_NUMBER: _ClassVar[int]
    UP_TO_DATE_FIELD_NUMBER: _ClassVar[int]
    NONCES_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    OWNER_USERNAME_FIELD_NUMBER: _ClassVar[int]
    ABUSE_REPORTING_ENABLED_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    GEOBLOCK_FIELD_NUMBER: _ClassVar[int]
    CHANGES_REQUIRE_RESYNC_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    APPLIED_LENSES_FIELD_NUMBER: _ClassVar[int]
    revision: bytes
    length: int
    attributes: ListAttributes
    contents: ListItems
    diff: Diff
    sync_result: Diff
    resulting_revisions: _containers.RepeatedScalarFieldContainer[bytes]
    multiple_heads: bool
    up_to_date: bool
    nonces: _containers.RepeatedScalarFieldContainer[int]
    timestamp: int
    owner_username: str
    abuse_reporting_enabled: bool
    capabilities: _playlist_permission_pb2.Capabilities
    geoblock: _containers.RepeatedScalarFieldContainer[GeoblockBlockingType]
    changes_require_resync: bool
    created_at: int
    applied_lenses: AppliedLenses
    def __init__(self, revision: _Optional[bytes] = ..., length: _Optional[int] = ..., attributes: _Optional[_Union[ListAttributes, _Mapping]] = ..., contents: _Optional[_Union[ListItems, _Mapping]] = ..., diff: _Optional[_Union[Diff, _Mapping]] = ..., sync_result: _Optional[_Union[Diff, _Mapping]] = ..., resulting_revisions: _Optional[_Iterable[bytes]] = ..., multiple_heads: _Optional[bool] = ..., up_to_date: _Optional[bool] = ..., nonces: _Optional[_Iterable[int]] = ..., timestamp: _Optional[int] = ..., owner_username: _Optional[str] = ..., abuse_reporting_enabled: _Optional[bool] = ..., capabilities: _Optional[_Union[_playlist_permission_pb2.Capabilities, _Mapping]] = ..., geoblock: _Optional[_Iterable[_Union[GeoblockBlockingType, str]]] = ..., changes_require_resync: _Optional[bool] = ..., created_at: _Optional[int] = ..., applied_lenses: _Optional[_Union[AppliedLenses, _Mapping]] = ...) -> None: ...

class AppliedLenses(_message.Message):
    __slots__ = ("states",)
    STATES_FIELD_NUMBER: _ClassVar[int]
    states: _containers.RepeatedCompositeFieldContainer[_lens_model_pb2.LensState]
    def __init__(self, states: _Optional[_Iterable[_Union[_lens_model_pb2.LensState, _Mapping]]] = ...) -> None: ...

class CreateListReply(_message.Message):
    __slots__ = ("uri", "revision")
    URI_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    uri: str
    revision: bytes
    def __init__(self, uri: _Optional[str] = ..., revision: _Optional[bytes] = ...) -> None: ...

class PlaylistV1UriRequest(_message.Message):
    __slots__ = ("v2_uris",)
    V2_URIS_FIELD_NUMBER: _ClassVar[int]
    v2_uris: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, v2_uris: _Optional[_Iterable[str]] = ...) -> None: ...

class PlaylistV1UriReply(_message.Message):
    __slots__ = ("v2_uri_to_v1_uri",)
    class V2UriToV1UriEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    V2_URI_TO_V1_URI_FIELD_NUMBER: _ClassVar[int]
    v2_uri_to_v1_uri: _containers.ScalarMap[str, str]
    def __init__(self, v2_uri_to_v1_uri: _Optional[_Mapping[str, str]] = ...) -> None: ...

class ListUpdateRequest(_message.Message):
    __slots__ = ("base_revision", "attributes", "items", "info")
    BASE_REVISION_FIELD_NUMBER: _ClassVar[int]
    ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    INFO_FIELD_NUMBER: _ClassVar[int]
    base_revision: bytes
    attributes: ListAttributes
    items: _containers.RepeatedCompositeFieldContainer[Item]
    info: ChangeInfo
    def __init__(self, base_revision: _Optional[bytes] = ..., attributes: _Optional[_Union[ListAttributes, _Mapping]] = ..., items: _Optional[_Iterable[_Union[Item, _Mapping]]] = ..., info: _Optional[_Union[ChangeInfo, _Mapping]] = ...) -> None: ...

class RegisterPlaylistImageRequest(_message.Message):
    __slots__ = ("upload_token",)
    UPLOAD_TOKEN_FIELD_NUMBER: _ClassVar[int]
    upload_token: str
    def __init__(self, upload_token: _Optional[str] = ...) -> None: ...

class RegisterPlaylistImageResponse(_message.Message):
    __slots__ = ("picture",)
    PICTURE_FIELD_NUMBER: _ClassVar[int]
    picture: bytes
    def __init__(self, picture: _Optional[bytes] = ...) -> None: ...

class ResolvedPersonalizedPlaylist(_message.Message):
    __slots__ = ("uri", "tag")
    URI_FIELD_NUMBER: _ClassVar[int]
    TAG_FIELD_NUMBER: _ClassVar[int]
    uri: str
    tag: str
    def __init__(self, uri: _Optional[str] = ..., tag: _Optional[str] = ...) -> None: ...

class PlaylistUriResolverResponse(_message.Message):
    __slots__ = ("resolved_playlists",)
    RESOLVED_PLAYLISTS_FIELD_NUMBER: _ClassVar[int]
    resolved_playlists: _containers.RepeatedCompositeFieldContainer[ResolvedPersonalizedPlaylist]
    def __init__(self, resolved_playlists: _Optional[_Iterable[_Union[ResolvedPersonalizedPlaylist, _Mapping]]] = ...) -> None: ...

class SubscribeRequest(_message.Message):
    __slots__ = ("uris",)
    URIS_FIELD_NUMBER: _ClassVar[int]
    uris: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, uris: _Optional[_Iterable[bytes]] = ...) -> None: ...

class UnsubscribeRequest(_message.Message):
    __slots__ = ("uris",)
    URIS_FIELD_NUMBER: _ClassVar[int]
    uris: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, uris: _Optional[_Iterable[bytes]] = ...) -> None: ...

class PlaylistModificationInfo(_message.Message):
    __slots__ = ("uri", "new_revision", "parent_revision", "ops")
    URI_FIELD_NUMBER: _ClassVar[int]
    NEW_REVISION_FIELD_NUMBER: _ClassVar[int]
    PARENT_REVISION_FIELD_NUMBER: _ClassVar[int]
    OPS_FIELD_NUMBER: _ClassVar[int]
    uri: bytes
    new_revision: bytes
    parent_revision: bytes
    ops: _containers.RepeatedCompositeFieldContainer[Op]
    def __init__(self, uri: _Optional[bytes] = ..., new_revision: _Optional[bytes] = ..., parent_revision: _Optional[bytes] = ..., ops: _Optional[_Iterable[_Union[Op, _Mapping]]] = ...) -> None: ...

class RootlistModificationInfo(_message.Message):
    __slots__ = ("new_revision", "parent_revision", "ops")
    NEW_REVISION_FIELD_NUMBER: _ClassVar[int]
    PARENT_REVISION_FIELD_NUMBER: _ClassVar[int]
    OPS_FIELD_NUMBER: _ClassVar[int]
    new_revision: bytes
    parent_revision: bytes
    ops: _containers.RepeatedCompositeFieldContainer[Op]
    def __init__(self, new_revision: _Optional[bytes] = ..., parent_revision: _Optional[bytes] = ..., ops: _Optional[_Iterable[_Union[Op, _Mapping]]] = ...) -> None: ...

class FollowerUpdate(_message.Message):
    __slots__ = ("uri", "username", "is_following", "timestamp")
    URI_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    IS_FOLLOWING_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    uri: str
    username: str
    is_following: bool
    timestamp: int
    def __init__(self, uri: _Optional[str] = ..., username: _Optional[str] = ..., is_following: _Optional[bool] = ..., timestamp: _Optional[int] = ...) -> None: ...
