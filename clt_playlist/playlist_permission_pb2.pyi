from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class PermissionLevel(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UNKNOWN: _ClassVar[PermissionLevel]
    BLOCKED: _ClassVar[PermissionLevel]
    VIEWER: _ClassVar[PermissionLevel]
    CONTRIBUTOR: _ClassVar[PermissionLevel]
    MADE_FOR: _ClassVar[PermissionLevel]

class PermissionIdentifierKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PERMISSION_IDENTIFIER_KIND_UNSPECIFIED: _ClassVar[PermissionIdentifierKind]
    PERMISSION_IDENTIFIER_KIND_BASE: _ClassVar[PermissionIdentifierKind]
    PERMISSION_IDENTIFIER_KIND_MEMBER: _ClassVar[PermissionIdentifierKind]
    PERMISSION_IDENTIFIER_KIND_ABUSE: _ClassVar[PermissionIdentifierKind]
    PERMISSION_IDENTIFIER_KIND_PROFILE: _ClassVar[PermissionIdentifierKind]
    PERMISSION_IDENTIFIER_KIND_AUTHORIZED: _ClassVar[PermissionIdentifierKind]
UNKNOWN: PermissionLevel
BLOCKED: PermissionLevel
VIEWER: PermissionLevel
CONTRIBUTOR: PermissionLevel
MADE_FOR: PermissionLevel
PERMISSION_IDENTIFIER_KIND_UNSPECIFIED: PermissionIdentifierKind
PERMISSION_IDENTIFIER_KIND_BASE: PermissionIdentifierKind
PERMISSION_IDENTIFIER_KIND_MEMBER: PermissionIdentifierKind
PERMISSION_IDENTIFIER_KIND_ABUSE: PermissionIdentifierKind
PERMISSION_IDENTIFIER_KIND_PROFILE: PermissionIdentifierKind
PERMISSION_IDENTIFIER_KIND_AUTHORIZED: PermissionIdentifierKind

class Permission(_message.Message):
    __slots__ = ("revision", "permission_level")
    REVISION_FIELD_NUMBER: _ClassVar[int]
    PERMISSION_LEVEL_FIELD_NUMBER: _ClassVar[int]
    revision: bytes
    permission_level: PermissionLevel
    def __init__(self, revision: _Optional[bytes] = ..., permission_level: _Optional[_Union[PermissionLevel, str]] = ...) -> None: ...

class GrantableLevels(_message.Message):
    __slots__ = ("base", "member")
    BASE_FIELD_NUMBER: _ClassVar[int]
    MEMBER_FIELD_NUMBER: _ClassVar[int]
    base: _containers.RepeatedScalarFieldContainer[PermissionLevel]
    member: _containers.RepeatedScalarFieldContainer[PermissionLevel]
    def __init__(self, base: _Optional[_Iterable[_Union[PermissionLevel, str]]] = ..., member: _Optional[_Iterable[_Union[PermissionLevel, str]]] = ...) -> None: ...

class AttributeCapabilities(_message.Message):
    __slots__ = ("can_edit",)
    CAN_EDIT_FIELD_NUMBER: _ClassVar[int]
    can_edit: bool
    def __init__(self, can_edit: _Optional[bool] = ...) -> None: ...

class ListAttributeCapabilities(_message.Message):
    __slots__ = ("name", "description", "picture", "collaborative", "deleted_by_owner", "ai_curation_reference_id")
    NAME_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    PICTURE_FIELD_NUMBER: _ClassVar[int]
    COLLABORATIVE_FIELD_NUMBER: _ClassVar[int]
    DELETED_BY_OWNER_FIELD_NUMBER: _ClassVar[int]
    AI_CURATION_REFERENCE_ID_FIELD_NUMBER: _ClassVar[int]
    name: AttributeCapabilities
    description: AttributeCapabilities
    picture: AttributeCapabilities
    collaborative: AttributeCapabilities
    deleted_by_owner: AttributeCapabilities
    ai_curation_reference_id: AttributeCapabilities
    def __init__(self, name: _Optional[_Union[AttributeCapabilities, _Mapping]] = ..., description: _Optional[_Union[AttributeCapabilities, _Mapping]] = ..., picture: _Optional[_Union[AttributeCapabilities, _Mapping]] = ..., collaborative: _Optional[_Union[AttributeCapabilities, _Mapping]] = ..., deleted_by_owner: _Optional[_Union[AttributeCapabilities, _Mapping]] = ..., ai_curation_reference_id: _Optional[_Union[AttributeCapabilities, _Mapping]] = ...) -> None: ...

class Capabilities(_message.Message):
    __slots__ = ("can_view", "can_administrate_permissions", "grantable_level", "can_edit_metadata", "can_edit_items", "can_cancel_membership", "grantable_levels", "list_attribute_capabilities")
    CAN_VIEW_FIELD_NUMBER: _ClassVar[int]
    CAN_ADMINISTRATE_PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    GRANTABLE_LEVEL_FIELD_NUMBER: _ClassVar[int]
    CAN_EDIT_METADATA_FIELD_NUMBER: _ClassVar[int]
    CAN_EDIT_ITEMS_FIELD_NUMBER: _ClassVar[int]
    CAN_CANCEL_MEMBERSHIP_FIELD_NUMBER: _ClassVar[int]
    GRANTABLE_LEVELS_FIELD_NUMBER: _ClassVar[int]
    LIST_ATTRIBUTE_CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    can_view: bool
    can_administrate_permissions: bool
    grantable_level: _containers.RepeatedScalarFieldContainer[PermissionLevel]
    can_edit_metadata: bool
    can_edit_items: bool
    can_cancel_membership: bool
    grantable_levels: GrantableLevels
    list_attribute_capabilities: ListAttributeCapabilities
    def __init__(self, can_view: _Optional[bool] = ..., can_administrate_permissions: _Optional[bool] = ..., grantable_level: _Optional[_Iterable[_Union[PermissionLevel, str]]] = ..., can_edit_metadata: _Optional[bool] = ..., can_edit_items: _Optional[bool] = ..., can_cancel_membership: _Optional[bool] = ..., grantable_levels: _Optional[_Union[GrantableLevels, _Mapping]] = ..., list_attribute_capabilities: _Optional[_Union[ListAttributeCapabilities, _Mapping]] = ...) -> None: ...

class CapabilitiesMultiRequest(_message.Message):
    __slots__ = ("request", "fallback_username", "fallback_user_id", "fallback_uri")
    REQUEST_FIELD_NUMBER: _ClassVar[int]
    FALLBACK_USERNAME_FIELD_NUMBER: _ClassVar[int]
    FALLBACK_USER_ID_FIELD_NUMBER: _ClassVar[int]
    FALLBACK_URI_FIELD_NUMBER: _ClassVar[int]
    request: _containers.RepeatedCompositeFieldContainer[CapabilitiesRequest]
    fallback_username: str
    fallback_user_id: str
    fallback_uri: str
    def __init__(self, request: _Optional[_Iterable[_Union[CapabilitiesRequest, _Mapping]]] = ..., fallback_username: _Optional[str] = ..., fallback_user_id: _Optional[str] = ..., fallback_uri: _Optional[str] = ...) -> None: ...

class CapabilitiesRequestOptions(_message.Message):
    __slots__ = ("can_view_only",)
    CAN_VIEW_ONLY_FIELD_NUMBER: _ClassVar[int]
    can_view_only: bool
    def __init__(self, can_view_only: _Optional[bool] = ...) -> None: ...

class CapabilitiesRequest(_message.Message):
    __slots__ = ("username", "user_id", "uri", "user_is_owner", "permission_grant_token", "request_options")
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    URI_FIELD_NUMBER: _ClassVar[int]
    USER_IS_OWNER_FIELD_NUMBER: _ClassVar[int]
    PERMISSION_GRANT_TOKEN_FIELD_NUMBER: _ClassVar[int]
    REQUEST_OPTIONS_FIELD_NUMBER: _ClassVar[int]
    username: str
    user_id: str
    uri: str
    user_is_owner: bool
    permission_grant_token: str
    request_options: CapabilitiesRequestOptions
    def __init__(self, username: _Optional[str] = ..., user_id: _Optional[str] = ..., uri: _Optional[str] = ..., user_is_owner: _Optional[bool] = ..., permission_grant_token: _Optional[str] = ..., request_options: _Optional[_Union[CapabilitiesRequestOptions, _Mapping]] = ...) -> None: ...

class CapabilitiesMultiResponse(_message.Message):
    __slots__ = ("response",)
    RESPONSE_FIELD_NUMBER: _ClassVar[int]
    response: _containers.RepeatedCompositeFieldContainer[CapabilitiesResponse]
    def __init__(self, response: _Optional[_Iterable[_Union[CapabilitiesResponse, _Mapping]]] = ...) -> None: ...

class CapabilitiesResponse(_message.Message):
    __slots__ = ("status", "capabilities")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    status: ResponseStatus
    capabilities: Capabilities
    def __init__(self, status: _Optional[_Union[ResponseStatus, _Mapping]] = ..., capabilities: _Optional[_Union[Capabilities, _Mapping]] = ...) -> None: ...

class SetPermissionLevelRequest(_message.Message):
    __slots__ = ("permission_level",)
    PERMISSION_LEVEL_FIELD_NUMBER: _ClassVar[int]
    permission_level: PermissionLevel
    def __init__(self, permission_level: _Optional[_Union[PermissionLevel, str]] = ...) -> None: ...

class SetPermissionResponse(_message.Message):
    __slots__ = ("resulting_permission",)
    RESULTING_PERMISSION_FIELD_NUMBER: _ClassVar[int]
    resulting_permission: Permission
    def __init__(self, resulting_permission: _Optional[_Union[Permission, _Mapping]] = ...) -> None: ...

class GetMemberPermissionsResponse(_message.Message):
    __slots__ = ("member_permissions",)
    class MemberPermissionsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: Permission
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[Permission, _Mapping]] = ...) -> None: ...
    MEMBER_PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    member_permissions: _containers.MessageMap[str, Permission]
    def __init__(self, member_permissions: _Optional[_Mapping[str, Permission]] = ...) -> None: ...

class Permissions(_message.Message):
    __slots__ = ("base_permission",)
    BASE_PERMISSION_FIELD_NUMBER: _ClassVar[int]
    base_permission: Permission
    def __init__(self, base_permission: _Optional[_Union[Permission, _Mapping]] = ...) -> None: ...

class PermissionState(_message.Message):
    __slots__ = ("permissions", "capabilities", "is_private", "is_collaborative")
    PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    IS_PRIVATE_FIELD_NUMBER: _ClassVar[int]
    IS_COLLABORATIVE_FIELD_NUMBER: _ClassVar[int]
    permissions: Permissions
    capabilities: Capabilities
    is_private: bool
    is_collaborative: bool
    def __init__(self, permissions: _Optional[_Union[Permissions, _Mapping]] = ..., capabilities: _Optional[_Union[Capabilities, _Mapping]] = ..., is_private: _Optional[bool] = ..., is_collaborative: _Optional[bool] = ...) -> None: ...

class PermissionStatePub(_message.Message):
    __slots__ = ("permission_state",)
    PERMISSION_STATE_FIELD_NUMBER: _ClassVar[int]
    permission_state: PermissionState
    def __init__(self, permission_state: _Optional[_Union[PermissionState, _Mapping]] = ...) -> None: ...

class PermissionGrantOptions(_message.Message):
    __slots__ = ("permission", "ttl_ms")
    PERMISSION_FIELD_NUMBER: _ClassVar[int]
    TTL_MS_FIELD_NUMBER: _ClassVar[int]
    permission: Permission
    ttl_ms: int
    def __init__(self, permission: _Optional[_Union[Permission, _Mapping]] = ..., ttl_ms: _Optional[int] = ...) -> None: ...

class PermissionGrant(_message.Message):
    __slots__ = ("token", "permission_grant_options")
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    PERMISSION_GRANT_OPTIONS_FIELD_NUMBER: _ClassVar[int]
    token: str
    permission_grant_options: PermissionGrantOptions
    def __init__(self, token: _Optional[str] = ..., permission_grant_options: _Optional[_Union[PermissionGrantOptions, _Mapping]] = ...) -> None: ...

class PermissionGrantDetails(_message.Message):
    __slots__ = ("permission_level_downgraded",)
    PERMISSION_LEVEL_DOWNGRADED_FIELD_NUMBER: _ClassVar[int]
    permission_level_downgraded: bool
    def __init__(self, permission_level_downgraded: _Optional[bool] = ...) -> None: ...

class PermissionGrantDescription(_message.Message):
    __slots__ = ("permission_grant_options", "claim_fail_reason", "is_effective", "capabilities", "details")
    class ClaimFailReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        CLAIM_FAIL_REASON_UNSPECIFIED: _ClassVar[PermissionGrantDescription.ClaimFailReason]
        CLAIM_FAIL_REASON_ANONYMOUS: _ClassVar[PermissionGrantDescription.ClaimFailReason]
        CLAIM_FAIL_REASON_NO_GRANT_FOUND: _ClassVar[PermissionGrantDescription.ClaimFailReason]
        CLAIM_FAIL_REASON_GRANT_EXPIRED: _ClassVar[PermissionGrantDescription.ClaimFailReason]
    CLAIM_FAIL_REASON_UNSPECIFIED: PermissionGrantDescription.ClaimFailReason
    CLAIM_FAIL_REASON_ANONYMOUS: PermissionGrantDescription.ClaimFailReason
    CLAIM_FAIL_REASON_NO_GRANT_FOUND: PermissionGrantDescription.ClaimFailReason
    CLAIM_FAIL_REASON_GRANT_EXPIRED: PermissionGrantDescription.ClaimFailReason
    PERMISSION_GRANT_OPTIONS_FIELD_NUMBER: _ClassVar[int]
    CLAIM_FAIL_REASON_FIELD_NUMBER: _ClassVar[int]
    IS_EFFECTIVE_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    DETAILS_FIELD_NUMBER: _ClassVar[int]
    permission_grant_options: PermissionGrantOptions
    claim_fail_reason: PermissionGrantDescription.ClaimFailReason
    is_effective: bool
    capabilities: Capabilities
    details: _containers.RepeatedCompositeFieldContainer[PermissionGrantDetails]
    def __init__(self, permission_grant_options: _Optional[_Union[PermissionGrantOptions, _Mapping]] = ..., claim_fail_reason: _Optional[_Union[PermissionGrantDescription.ClaimFailReason, str]] = ..., is_effective: _Optional[bool] = ..., capabilities: _Optional[_Union[Capabilities, _Mapping]] = ..., details: _Optional[_Iterable[_Union[PermissionGrantDetails, _Mapping]]] = ...) -> None: ...

class ClaimPermissionGrantResponse(_message.Message):
    __slots__ = ("user_permission", "capabilities", "details")
    USER_PERMISSION_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    DETAILS_FIELD_NUMBER: _ClassVar[int]
    user_permission: Permission
    capabilities: Capabilities
    details: _containers.RepeatedCompositeFieldContainer[PermissionGrantDetails]
    def __init__(self, user_permission: _Optional[_Union[Permission, _Mapping]] = ..., capabilities: _Optional[_Union[Capabilities, _Mapping]] = ..., details: _Optional[_Iterable[_Union[PermissionGrantDetails, _Mapping]]] = ...) -> None: ...

class ResponseStatus(_message.Message):
    __slots__ = ("status_code", "status_message")
    STATUS_CODE_FIELD_NUMBER: _ClassVar[int]
    STATUS_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    status_code: int
    status_message: str
    def __init__(self, status_code: _Optional[int] = ..., status_message: _Optional[str] = ...) -> None: ...

class PermissionIdentifier(_message.Message):
    __slots__ = ("kind", "user_id")
    KIND_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    kind: PermissionIdentifierKind
    user_id: str
    def __init__(self, kind: _Optional[_Union[PermissionIdentifierKind, str]] = ..., user_id: _Optional[str] = ...) -> None: ...

class PermissionEntry(_message.Message):
    __slots__ = ("identifier", "permission")
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    PERMISSION_FIELD_NUMBER: _ClassVar[int]
    identifier: PermissionIdentifier
    permission: Permission
    def __init__(self, identifier: _Optional[_Union[PermissionIdentifier, _Mapping]] = ..., permission: _Optional[_Union[Permission, _Mapping]] = ...) -> None: ...

class CreateInitialPermissions(_message.Message):
    __slots__ = ("permission_entry",)
    PERMISSION_ENTRY_FIELD_NUMBER: _ClassVar[int]
    permission_entry: _containers.RepeatedCompositeFieldContainer[PermissionEntry]
    def __init__(self, permission_entry: _Optional[_Iterable[_Union[PermissionEntry, _Mapping]]] = ...) -> None: ...

class CreateInitialPermissionsResponse(_message.Message):
    __slots__ = ("permission_entry",)
    PERMISSION_ENTRY_FIELD_NUMBER: _ClassVar[int]
    permission_entry: _containers.RepeatedCompositeFieldContainer[PermissionEntry]
    def __init__(self, permission_entry: _Optional[_Iterable[_Union[PermissionEntry, _Mapping]]] = ...) -> None: ...

class DefaultOwnerCapabilitiesResponse(_message.Message):
    __slots__ = ("capabilities",)
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    capabilities: Capabilities
    def __init__(self, capabilities: _Optional[_Union[Capabilities, _Mapping]] = ...) -> None: ...
