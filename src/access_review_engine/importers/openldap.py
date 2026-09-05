from __future__ import annotations

from base64 import b64decode
from pathlib import Path

from access_review_engine.domain import (
    Access,
    AccessAssignment,
    AssignmentType,
    ControlObject,
    Identity,
    IdentityStatus,
    IdentityType,
    ImportBatch,
    ImportStatus,
    Origin,
    Permission,
    Provider,
    ProviderType,
    stable_checksum,
)
from access_review_engine.importers.ad import ImportResult


def import_openldap_ldif(path: str | Path, provider_name: str = "openldap") -> ImportResult:
    text = Path(path).read_text(encoding="utf-8")
    entries = _parse_ldif(text)
    provider = Provider(name=provider_name, type=ProviderType.OPENLDAP, display_name=provider_name)
    identities: list[Identity] = []
    groups: list[dict[str, list[str]]] = []
    for entry in entries:
        classes = {value.lower() for value in entry.get("objectclass", [])}
        if "inetorgperson" in classes:
            uid = _first(entry, "uid") or _first(entry, "cn") or _first(entry, "dn")
            identities.append(
                Identity(
                    provider=provider.name,
                    identifier=uid,
                    native_id=_first(entry, "entryuuid") or _first(entry, "dn"),
                    type=IdentityType.USER_ACCOUNT,
                    status=IdentityStatus.ACTIVE,
                    display_name=_first(entry, "cn"),
                    email=_first(entry, "mail"),
                    description=_first(entry, "description"),
                    metadata={"dn": _first(entry, "dn")},
                )
            )
        if classes & {"groupofnames", "groupofuniquenames", "posixgroup"}:
            groups.append(entry)
            cn = _first(entry, "cn") or _first(entry, "dn")
            identities.append(
                Identity(
                    provider=provider.name,
                    identifier=cn,
                    native_id=_first(entry, "entryuuid") or _first(entry, "dn"),
                    type=IdentityType.GROUP,
                    status=IdentityStatus.ACTIVE,
                    display_name=cn,
                    description=_first(entry, "description"),
                    metadata={"dn": _first(entry, "dn")},
                )
            )
    accesses: list[Access] = []
    assignments: list[AccessAssignment] = []
    for group in groups:
        cn = _first(group, "cn") or _first(group, "dn")
        description = _first(group, "description")
        access_name = f"{cn}:member"
        accesses.append(
            Access(
                name=access_name,
                provider=provider.name,
                control_object=ControlObject("group", cn, _first(group, "entryuuid"), cn, description),
                permission=Permission("member", "Member"),
                description=description,
            )
        )
        for member in group.get("member", []) + group.get("uniquemember", []) + group.get("memberuid", []):
            assignments.append(
                AccessAssignment(
                    provider=provider.name,
                    access_name=access_name,
                    identity_provider=provider.name,
                    identity_identifier=_member_identifier(member),
                    origin=Origin(
                        assignment_type=AssignmentType.GROUP,
                        direct=True,
                        inherited=False,
                        source=cn,
                        raw={"member": member},
                    ),
                )
            )
    batch = ImportBatch(
        provider=provider.name,
        source_type="openldap_ldif",
        status=ImportStatus.COMPLETED,
        completeness="full",
        scope={"type": "all"},
        checksum=stable_checksum(entries),
    )
    from access_review_engine.domain import now_utc

    batch.completed_at = now_utc()
    return ImportResult(batch, provider, identities, accesses, assignments)


def _parse_ldif(text: str) -> list[dict[str, list[str]]]:
    entries: list[dict[str, list[str]]] = []
    current: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line.strip():
            if current:
                entries.append(current)
                current = {}
            continue
        if line.startswith((" ", "\t")) and current:
            key = next(reversed(current))
            current[key][-1] += line[1:]
            continue
        if line.startswith("#") or ":" not in line:
            continue
        if "::" in line:
            key, value = line.split("::", 1)
            decoded = b64decode(value.strip()).decode("utf-8")
            current.setdefault(_attr_key(key), []).append(decoded)
            continue
        key, value = line.split(":", 1)
        current.setdefault(_attr_key(key), []).append(value.strip())
    if current:
        entries.append(current)
    return entries


def _attr_key(key: str) -> str:
    return key.split(";", 1)[0].strip().lower()


def _first(entry: dict[str, list[str]], key: str) -> str | None:
    values = entry.get(key)
    return values[0] if values else None


def _member_identifier(value: str) -> str:
    if "=" in value and "," in value:
        first = value.split(",", 1)[0]
        return first.split("=", 1)[1]
    return value
