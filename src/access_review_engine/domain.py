from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
import json
from typing import Any
from uuid import uuid4


JsonDict = dict[str, Any]


class ProviderType(StrEnum):
    ACTIVE_DIRECTORY = "active_directory"
    OPENLDAP = "openldap"
    GENERIC = "generic"


class IdentityType(StrEnum):
    USER_ACCOUNT = "user_account"
    TECHNICAL_ACCOUNT = "technical_account"
    SHARED_ACCOUNT = "shared_account"
    GROUP = "group"


class IdentityStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    DELETED = "deleted"
    UNKNOWN = "unknown"


class AssignmentType(StrEnum):
    DIRECT = "direct"
    GROUP = "group"
    ROLE = "role"
    POLICY = "policy"
    INHERITED = "inherited"
    UNKNOWN = "unknown"


class ImportStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Completeness(StrEnum):
    FULL = "full"
    SCOPED = "scoped"
    UNKNOWN = "unknown"


class ComparisonState(StrEnum):
    EXPECTED_AND_OBSERVED = "expected_and_observed"
    UNEXPECTED = "unexpected"
    MISSING = "missing"
    UNKNOWN_DUE_TO_SCOPE = "unknown_due_to_scope"
    NO_REFERENCE = "no_reference"


class Finding(StrEnum):
    DISABLED_WITH_ACCESS = "disabled_with_access"
    DELETED_WITH_ACCESS = "deleted_with_access"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_EXPIRED = "account_expired"
    TECHNICAL_ACCOUNT_WITHOUT_OWNER = "technical_account_without_owner"
    SHARED_ACCOUNT_WITHOUT_OWNER = "shared_account_without_owner"
    INVALID_OWNER = "invalid_owner"
    UNKNOWN_IDENTITY = "unknown_identity"
    UNRESOLVED_FOREIGN_PRINCIPAL = "unresolved_foreign_principal"
    COLLECTION_INCOMPLETE = "collection_incomplete"
    UNKNOWN_MEMBER_TYPE = "unknown_member_type"


class CampaignStatus(StrEnum):
    DRAFT = "draft"
    OPEN = "open"
    CLOSED = "closed"
    CANCELLED = "cancelled"


class DecisionValue(StrEnum):
    APPROVE = "approve"
    REVOKE = "revoke"
    NOT_APPLICABLE = "not_applicable"


class RemediationActionType(StrEnum):
    GRANT = "grant"
    REVOKE = "revoke"


class RemediationStatus(StrEnum):
    PENDING = "pending"
    EXPORTED = "exported"


def now_utc() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def new_id() -> str:
    return str(uuid4())


def stable_json(value: Any) -> str:
    def default(obj: Any) -> Any:
        if is_dataclass(obj):
            return asdict(obj)
        if isinstance(obj, StrEnum):
            return str(obj)
        raise TypeError(f"Unsupported type for stable JSON: {type(obj)!r}")

    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=default)


def stable_checksum(value: Any) -> str:
    return sha256(stable_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ObjectRef:
    provider: str
    identifier: str

    def key(self) -> str:
        return f"{self.provider}:{self.identifier}"


@dataclass
class Provider:
    name: str
    type: str
    display_name: str | None = None
    description: str | None = None
    id: str = field(default_factory=new_id)
    created_at: str = field(default_factory=now_utc)
    updated_at: str = field(default_factory=now_utc)


@dataclass
class OwnerRef:
    provider: str
    identity: str

    def object_ref(self) -> ObjectRef:
        return ObjectRef(self.provider, self.identity)


@dataclass
class Identity:
    provider: str
    identifier: str
    type: str
    status: str
    native_id: str | None = None
    subject_id: str | None = None
    display_name: str | None = None
    email: str | None = None
    description: str | None = None
    account_owner: OwnerRef | None = None
    built_in: bool = False
    metadata: JsonDict = field(default_factory=dict)
    id: str = field(default_factory=new_id)

    def ref(self) -> ObjectRef:
        return ObjectRef(self.provider, self.identifier)


@dataclass
class Resource:
    provider: str
    type: str
    identifier: str
    native_id: str | None = None
    display_name: str | None = None
    description: str | None = None
    metadata: JsonDict = field(default_factory=dict)
    id: str = field(default_factory=new_id)


@dataclass
class ControlObject:
    type: str
    identifier: str
    native_id: str | None = None
    display_name: str | None = None
    description: str | None = None
    metadata: JsonDict = field(default_factory=dict)


@dataclass
class Permission:
    identifier: str
    display_name: str | None = None
    description: str | None = None
    metadata: JsonDict = field(default_factory=dict)


@dataclass
class Target:
    service: JsonDict | None = None
    component: JsonDict | None = None
    resource: JsonDict | None = None


@dataclass
class Access:
    name: str
    provider: str
    control_object: ControlObject
    permission: Permission
    target: Target | None = None
    display_name: str | None = None
    description: str | None = None
    access_owner: OwnerRef | None = None
    metadata: JsonDict = field(default_factory=dict)
    id: str = field(default_factory=new_id)

    def key(self) -> str:
        return f"{self.provider}:{self.name}"


@dataclass
class Origin:
    assignment_type: str
    direct: bool
    inherited: bool
    source: str | None = None
    raw: JsonDict = field(default_factory=dict)

    def fingerprint(self) -> str:
        return stable_checksum(asdict(self))


@dataclass
class AccessAssignment:
    provider: str
    access_name: str
    identity_provider: str
    identity_identifier: str
    origin: Origin
    id: str = field(default_factory=new_id)

    @property
    def origin_fingerprint(self) -> str:
        return self.origin.fingerprint()

    def comparison_key(self) -> tuple[str, str, str, str]:
        return (self.provider, self.access_name, self.identity_provider, self.identity_identifier)


@dataclass
class ImportBatch:
    provider: str
    source_type: str
    status: str
    completeness: str
    scope: JsonDict
    checksum: str
    id: str = field(default_factory=new_id)
    started_at: str = field(default_factory=now_utc)
    completed_at: str | None = None


@dataclass
class GoldenSource:
    name: str
    display_name: str | None = None
    description: str | None = None
    active_version_id: str | None = None
    created_by: str | None = None
    id: str = field(default_factory=new_id)
    created_at: str = field(default_factory=now_utc)


@dataclass(frozen=True)
class GoldenSourceAssignment:
    access_provider: str
    access_name: str
    identity_provider: str
    identity_identifier: str

    def key(self) -> tuple[str, str, str, str]:
        return (
            self.access_provider,
            self.access_name,
            self.identity_provider,
            self.identity_identifier,
        )


@dataclass
class GoldenSourceVersion:
    golden_source_id: str
    version: int
    source_type: str
    checksum: str
    assignments: list[GoldenSourceAssignment]
    source_snapshot_id: str | None = None
    source_campaign_id: str | None = None
    parent_version_id: str | None = None
    comment: str | None = None
    created_by: str | None = None
    id: str = field(default_factory=new_id)
    created_at: str = field(default_factory=now_utc)


@dataclass
class Snapshot:
    providers: list[Provider]
    identities: list[Identity]
    resources: list[Resource]
    accesses: list[Access]
    access_assignments: list[AccessAssignment]
    source_import_ids: list[str]
    comparison_states: list[JsonDict] = field(default_factory=list)
    id: str = field(default_factory=new_id)
    created_at: str = field(default_factory=now_utc)
    immutable: bool = True
    checksum: str = ""

    def finalize(self) -> "Snapshot":
        payload = asdict(self) | {"id": None, "created_at": None, "checksum": None}
        self.checksum = stable_checksum(payload)
        return self


@dataclass
class Campaign:
    name: str
    snapshot_id: str
    status: str = CampaignStatus.DRAFT
    display_name: str | None = None
    description: str | None = None
    golden_source_version_id: str | None = None
    scope: JsonDict = field(default_factory=lambda: {"type": "all"})
    default_reviewer: OwnerRef | None = None
    manager: OwnerRef | None = None
    allow_unresolved_reviewers: bool = False
    id: str = field(default_factory=new_id)
    created_at: str = field(default_factory=now_utc)
    opened_at: str | None = None
    closed_at: str | None = None
    due_at: str | None = None


@dataclass
class ReviewItem:
    campaign_id: str
    identity_provider: str
    identity_identifier: str
    identity_status: str
    access_provider: str
    access_name: str
    control_object: JsonDict
    permission: JsonDict
    target: JsonDict | None
    description: str | None
    origin: JsonDict | None
    expected: bool
    observed: bool
    classification: str
    findings: list[str]
    account_owner: OwnerRef | None
    access_owner: OwnerRef | None
    reviewer: OwnerRef | None
    id: str = field(default_factory=new_id)


@dataclass
class Decision:
    review_item_id: str
    value: str
    comment: str | None = None
    decided_by: str | None = None
    id: str = field(default_factory=new_id)
    created_at: str = field(default_factory=now_utc)


@dataclass
class AuditEvent:
    event_type: str
    actor: str | None = None
    object_type: str | None = None
    object_id: str | None = None
    details: JsonDict = field(default_factory=dict)
    id: str = field(default_factory=new_id)
    created_at: str = field(default_factory=now_utc)


@dataclass
class RemediationAction:
    review_item_id: str
    action: str
    status: str = RemediationStatus.PENDING
    details: JsonDict = field(default_factory=dict)
    id: str = field(default_factory=new_id)
    created_at: str = field(default_factory=now_utc)
