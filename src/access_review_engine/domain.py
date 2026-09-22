from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
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


class AccessRelationType(StrEnum):
    GRANTS = "grants"


class FunctionalModelCompleteness(StrEnum):
    NOT_DEFINED = "not_defined"
    PARTIAL = "partial"
    COMPLETE = "complete"


class Provenance(StrEnum):
    OBSERVED = "observed"
    MANUAL = "manual"
    MAPPED = "mapped"


class FunctionalComparisonState(StrEnum):
    EXPECTED_AND_OBSERVED = "expected_and_observed"
    MISSING = "missing"
    UNEXPECTED = "unexpected"
    UNKNOWN_NOT_ASSERTED = "unknown_not_asserted"
    NOT_DEFINED = "not_defined"


class ImportStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Completeness(StrEnum):
    FULL = "full"
    SCOPED = "scoped"
    UNKNOWN = "unknown"


class AuthenticationStatus(StrEnum):
    COLLECTED = "collected"
    NOT_CONFIGURED = "not_configured"
    NOT_SUPPORTED = "not_supported"
    NOT_COLLECTED = "not_collected"
    UNKNOWN = "unknown"
    ERROR = "error"


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


@dataclass(frozen=True)
class Capability:
    id: str
    label: str
    description: str
    active: bool = True
    system: bool = False

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("Capability ID is required")
        if not self.label.strip():
            raise ValueError("Capability label is required")
        if not self.description.strip():
            raise ValueError("Capability description is required")
        if self.id.casefold() == "membership":
            raise ValueError("Membership is not a functional capability")


@dataclass(frozen=True)
class PermissionCapabilityMapping:
    provider: str
    permission_identifier: str
    capability_ids: tuple[str, ...]
    provenance: str = Provenance.MAPPED

    def __post_init__(self) -> None:
        if not self.provider.strip() or not self.permission_identifier.strip():
            raise ValueError("Permission mapping requires provider and native permission")
        if not self.capability_ids:
            raise ValueError("Permission mapping requires at least one capability")


@dataclass(frozen=True)
class FunctionalRight:
    target: Target
    capability_id: str
    provenance: str = Provenance.MANUAL
    native_permission: str | None = None

    def __post_init__(self) -> None:
        if not self.capability_id.strip():
            raise ValueError("Functional right requires a capability")


@dataclass(frozen=True)
class ExpectedAccessModel:
    access_provider: str
    access_name: str
    completeness: str = FunctionalModelCompleteness.NOT_DEFINED
    rights: tuple[FunctionalRight, ...] = ()


@dataclass(frozen=True)
class GoldenAccessComment:
    access_provider: str
    access_name: str
    comment: str
    provenance: str = Provenance.MANUAL


SYSTEM_CAPABILITIES: tuple[Capability, ...] = (
    Capability("read", "Read", "View or retrieve information.", True, True),
    Capability("write", "Write", "Create or modify information.", True, True),
    Capability("delete", "Delete", "Remove information or objects.", True, True),
    Capability("execute", "Execute", "Run a command, process, or operation.", True, True),
    Capability("approve", "Approve", "Approve or validate a business operation.", True, True),
    Capability("admin", "Admin", "Administer a system, resource, or configuration.", True, True),
    Capability("grant", "Grant", "Grant or delegate access to others.", True, True),
)


def normalize_manual_target_node(value: JsonDict | None) -> JsonDict | None:
    """Validate a newly authored target node without rewriting historical values."""
    if value is None:
        return None
    identifier = value.get("identifier")
    if not isinstance(identifier, str) or not identifier.strip():
        raise ValueError("Manual Target identifier is required")
    normalized: JsonDict = {"identifier": identifier.strip()}
    display_name = value.get("display_name")
    node_type = value.get("type")
    metadata = value.get("metadata")
    if display_name is not None:
        if not isinstance(display_name, str):
            raise ValueError("Target display_name must be text")
        if display_name.strip():
            normalized["display_name"] = display_name.strip()
    if node_type is not None:
        if not isinstance(node_type, str) or not node_type.strip():
            raise ValueError("Target type must be non-empty text")
        normalized["type"] = node_type.strip()
    if metadata is not None:
        if not isinstance(metadata, dict):
            raise ValueError("Target metadata must be an object")
        normalized["metadata"] = metadata.copy()
    return normalized


def canonical_target_key(target: Target | None) -> tuple[tuple[str, str], ...]:
    if target is None:
        return ()
    result = []
    for level in ("service", "component", "resource"):
        node = getattr(target, level)
        if node is not None:
            identifier = node.get("identifier")
            if isinstance(identifier, str) and identifier.strip():
                result.append((level, identifier.strip()))
            else:
                legacy_identity = {key: item for key, item in node.items() if key != "display_name"}
                result.append((level, stable_json(legacy_identity)))
    return tuple(result)


def target_semantically_equal(left: Target | None, right: Target | None) -> bool:
    return canonical_target_key(left) == canonical_target_key(right)


def target_path(target: Target | None) -> str:
    if target is None:
        return ""
    labels = []
    for level in ("service", "component", "resource"):
        node = getattr(target, level)
        if node:
            label = node.get("display_name") or node.get("identifier") or node.get("name")
            if label:
                labels.append(str(label))
    return " › ".join(labels)


@dataclass
class Access:
    name: str
    provider: str
    control_object: ControlObject | None = None
    permission: Permission | None = None
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
class AccessRelation:
    parent_provider: str
    parent_access_name: str
    child_provider: str
    child_access_name: str
    relation_type: str
    origin: Origin
    metadata: JsonDict = field(default_factory=dict)
    id: str = field(default_factory=new_id)

    @property
    def origin_fingerprint(self) -> str:
        return self.origin.fingerprint()

    def key(self) -> tuple[str, str, str, str, str, str]:
        return (
            self.parent_provider,
            self.parent_access_name,
            self.child_provider,
            self.child_access_name,
            self.relation_type,
            self.origin_fingerprint,
        )

    def parent_key(self) -> tuple[str, str]:
        return (self.parent_provider, self.parent_access_name)

    def child_key(self) -> tuple[str, str]:
        return (self.child_provider, self.child_access_name)


@dataclass(frozen=True)
class AccessPath:
    identity_provider: str
    identity_identifier: str
    access_chain: tuple[ObjectRef, ...]
    assignment_id: str
    relation_ids: tuple[str, ...] = ()


@dataclass
class EffectiveAccess:
    identity_provider: str
    identity_identifier: str
    access_provider: str
    access_name: str
    direct: bool
    paths: list[AccessPath] = field(default_factory=list)

    def key(self) -> tuple[str, str, str, str]:
        return (
            self.identity_provider,
            self.identity_identifier,
            self.access_provider,
            self.access_name,
        )


@dataclass
class EffectiveAccessEvaluation:
    effective_accesses: list[EffectiveAccess]
    diagnostics: list[JsonDict] = field(default_factory=list)


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


def canonical_permission_id(permission: str | Permission | None) -> str:
    if isinstance(permission, Permission):
        return permission.identifier
    return permission or ""


@dataclass(frozen=True)
class GoldenSourceAssignment:
    access_provider: str
    access_name: str
    identity_provider: str
    identity_identifier: str
    access_native_id: str | None = None
    access_permission: str | None = None
    identity_native_id: str | None = None

    def key(self) -> tuple[str, str, str, str]:
        return (
            self.access_provider,
            self.access_name,
            self.identity_provider,
            self.identity_identifier,
        )

    def stable_key(self) -> tuple[str, str, str, str] | None:
        if not self.access_native_id and not self.identity_native_id:
            return None
        access_ref = (
            f"native:{self.access_native_id}:{canonical_permission_id(self.access_permission)}"
            if self.access_native_id
            else f"name:{self.access_name}"
        )
        identity_ref = (
            f"native:{self.identity_native_id}"
            if self.identity_native_id
            else f"identifier:{self.identity_identifier}"
        )
        return (self.access_provider, access_ref, self.identity_provider, identity_ref)


@dataclass
class AuthenticationPosture:
    provider: str
    controls: dict[str, JsonDict] = field(default_factory=dict)
    source: str | None = None
    completeness: str = str(Completeness.UNKNOWN)
    id: str = field(default_factory=new_id)
    collected_at: str = field(default_factory=now_utc)


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
    golden_authentication_policy: AuthenticationPosture | None = None
    id: str = field(default_factory=new_id)
    created_at: str = field(default_factory=now_utc)
    schema_version: int = 1
    expected_access_definitions: list[Access] = field(default_factory=list)
    expected_access_relations: list[AccessRelation] = field(default_factory=list)
    functional_access_models: list[ExpectedAccessModel] = field(default_factory=list)
    access_comments: list[GoldenAccessComment] = field(default_factory=list)


@dataclass
class Snapshot:
    providers: list[Provider]
    identities: list[Identity]
    resources: list[Resource]
    accesses: list[Access]
    access_assignments: list[AccessAssignment]
    source_import_ids: list[str]
    access_relations: list[AccessRelation] = field(default_factory=list)
    comparison_states: list[JsonDict] = field(default_factory=list)
    authentication_posture: AuthenticationPosture | None = None
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
    pilot: str | None = None
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
