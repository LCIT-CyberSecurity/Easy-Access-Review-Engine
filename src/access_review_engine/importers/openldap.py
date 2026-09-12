from __future__ import annotations

from base64 import b64decode
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from access_review_engine.domain import (
    Access,
    AccessAssignment,
    AuthenticationPosture,
    AuthenticationStatus,
    AssignmentType,
    Completeness,
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

REQUIRED_OPENLDAP_FILES = {"manifest.yaml", "directory.ldif"}
OPTIONAL_OPENLDAP_FILES = {"collection-errors.csv"}
ALLOWED_OPENLDAP_FILES = REQUIRED_OPENLDAP_FILES | OPTIONAL_OPENLDAP_FILES
MAX_OPENLDAP_ZIP_FILES = 8
DEFAULT_OPENLDAP_ARCHIVE_BYTES = 500_000_000
DEFAULT_OPENLDAP_FILE_BYTES = 250_000_000
DEFAULT_OPENLDAP_LDIF_BYTES = 1_000_000_000
DEFAULT_OPENLDAP_UNCOMPRESSED_BYTES = 1_500_000_000
SUPPORTED_SCHEMA_VERSIONS = {1}
SUPPORTED_COMPLETENESS = {Completeness.FULL, Completeness.SCOPED, Completeness.UNKNOWN}
USED_LDIF_ATTRIBUTES = {
    "dn",
    "objectclass",
    "entryuuid",
    "uid",
    "cn",
    "mail",
    "description",
    "member",
    "uniquemember",
    "memberuid",
    "changetype",
    "pwdminlength", "pwdinhistory", "pwdminage", "pwdmaxage", "pwdmaxfailure",
    "pwdfailurecountinterval", "pwdlockout", "pwdlockoutduration", "pwdmustchange",
    "pwdallowuserchange", "pwdsafemodify", "pwdpolicysubentry",
}
TEXT_LDIF_ATTRIBUTES = USED_LDIF_ATTRIBUTES
DEFAULT_OPENLDAP_FILTER = (
    "(|(objectClass=inetOrgPerson)(objectClass=posixAccount)"
    "(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup)(objectClass=pwdPolicy))"
)


def import_openldap_ldif(path: str | Path, provider_name: str = "openldap") -> ImportResult:
    text = Path(path).read_text(encoding="utf-8-sig")
    return _import_openldap_entries(
        _parse_ldif(text),
        provider_name=provider_name,
        source_type="openldap_ldif",
        completeness=str(Completeness.UNKNOWN),
        scope={"type": "all", "completeness": str(Completeness.UNKNOWN), "source": "raw_ldif"},
        trusted_export=False,
        manifest=None,
        collection_errors=[],
    )


def import_openldap_zip(
    path: str | Path,
    max_size_bytes: int = DEFAULT_OPENLDAP_ARCHIVE_BYTES,
    max_file_bytes: int = DEFAULT_OPENLDAP_FILE_BYTES,
    max_ldif_file_bytes: int = DEFAULT_OPENLDAP_LDIF_BYTES,
    max_uncompressed_bytes: int = DEFAULT_OPENLDAP_UNCOMPRESSED_BYTES,
) -> ImportResult:
    archive = Path(path)
    if archive.stat().st_size > max_size_bytes:
        raise ValueError("Import archive exceeds configured maximum size")
    try:
        with ZipFile(archive) as zf:
            names = zf.namelist()
            unique_names = set(names)
            if len(names) != len(unique_names):
                raise ValueError("Archive contains duplicate filenames")
            if len(names) > MAX_OPENLDAP_ZIP_FILES:
                raise ValueError("Archive contains too many files")
            if any(name.startswith("/") or ".." in Path(name).parts for name in names):
                raise ValueError("Unsafe ZIP path detected")
            if not ALLOWED_OPENLDAP_FILES.issuperset(unique_names):
                raise ValueError("Archive contains unexpected files")
            _validate_zip_members(zf, max_file_bytes, max_ldif_file_bytes, max_uncompressed_bytes)
            missing = REQUIRED_OPENLDAP_FILES - unique_names
            if missing:
                raise ValueError(f"Archive is missing required files: {sorted(missing)}")
            manifest = _read_manifest(zf.read("manifest.yaml").decode("utf-8-sig"))
            _validate_manifest(manifest)
            if manifest.get("source_type") != "openldap":
                raise ValueError("manifest.yaml has unsupported source_type")
            provider_name = manifest.get("provider") or manifest.get("provider_name")
            if not provider_name:
                raise ValueError("manifest.yaml must define provider")
            entries = _parse_ldif(zf.read("directory.ldif").decode("utf-8-sig"))
            collection_errors = _read_collection_errors(zf.read("collection-errors.csv").decode("utf-8-sig")) if "collection-errors.csv" in unique_names else []
    except BadZipFile as exc:
        raise ValueError("Invalid ZIP archive") from exc

    completeness = _effective_completeness(manifest, collection_errors)
    return _import_openldap_entries(
        entries,
        provider_name=str(provider_name),
        source_type="openldap_zip",
        completeness=completeness,
        scope=_effective_scope(manifest, completeness, collection_errors),
        trusted_export=True,
        manifest=manifest,
        collection_errors=collection_errors,
    )


def read_openldap_zip_manifest(path: str | Path) -> dict[str, object]:
    archive = Path(path)
    if archive.stat().st_size > DEFAULT_OPENLDAP_ARCHIVE_BYTES:
        raise ValueError("Import archive exceeds configured maximum size")
    try:
        with ZipFile(archive) as zf:
            names = zf.namelist()
            if len(names) != len(set(names)):
                raise ValueError("Archive contains duplicate filenames")
            if len(names) > MAX_OPENLDAP_ZIP_FILES:
                raise ValueError("Archive contains too many files")
            if any(name.startswith("/") or ".." in Path(name).parts for name in names):
                raise ValueError("Unsafe ZIP path detected")
            if "manifest.yaml" not in names:
                raise ValueError("Archive is missing required files: ['manifest.yaml']")
            _validate_zip_members(zf, DEFAULT_OPENLDAP_FILE_BYTES, DEFAULT_OPENLDAP_LDIF_BYTES, DEFAULT_OPENLDAP_UNCOMPRESSED_BYTES)
            return _read_manifest(zf.read("manifest.yaml").decode("utf-8-sig"))
    except BadZipFile as exc:
        raise ValueError("Invalid ZIP archive") from exc


def _import_openldap_entries(
    entries: list[dict[str, list[str]]],
    provider_name: str,
    source_type: str,
    completeness: str,
    scope: dict[str, object],
    trusted_export: bool,
    manifest: dict[str, object] | None,
    collection_errors: list[dict[str, str]],
) -> ImportResult:
    provider = Provider(name=provider_name, type=ProviderType.OPENLDAP, display_name=provider_name)
    by_dn = {_canonical_dn(_first(entry, "dn") or ""): entry for entry in entries if _first(entry, "dn")}
    identities: list[Identity] = []
    identity_by_dn: dict[str, Identity] = {}
    identity_by_uid: dict[str, list[Identity]] = {}
    groups: list[dict[str, list[str]]] = []

    for entry in entries:
        classes = {value.lower() for value in entry.get("objectclass", [])}
        if _is_user_entry(classes, entry):
            identity = _user_identity(provider.name, entry)
            identities.append(identity)
            dn = _first(entry, "dn")
            uid = _first(entry, "uid")
            if dn:
                identity_by_dn[_canonical_dn(dn)] = identity
            if uid:
                identity_by_uid.setdefault(uid, []).append(identity)
        if classes & {"groupofnames", "groupofuniquenames", "posixgroup"}:
            groups.append(entry)
            identity = _group_identity(provider.name, entry)
            identities.append(identity)
            dn = _first(entry, "dn")
            if dn:
                identity_by_dn[_canonical_dn(dn)] = identity

    accesses: list[Access] = []
    assignments: list[AccessAssignment] = []
    unresolved_in_scope = 0
    unresolved_total = 0
    for group in groups:
        group_identity = identity_by_dn[_canonical_dn(_first(group, "dn") or "")]
        cn = _first(group, "cn") or _first(group, "dn") or group_identity.identifier
        description = _first(group, "description")
        access_name = f"{group_identity.identifier}:member"
        accesses.append(
            Access(
                name=access_name,
                provider=provider.name,
                control_object=ControlObject("group", group_identity.identifier, group_identity.native_id, cn, description),
                permission=Permission("member", "Member"),
                display_name=f"{cn}:member",
                description=description,
            )
        )
        for attr in ("member", "uniquemember"):
            for member_value in group.get(attr, []):
                member_dn, optional_uid = (
                    _unique_member_dn_and_uid(member_value)
                    if attr == "uniquemember"
                    else (member_value, None)
                )
                identity = identity_by_dn.get(_canonical_dn(member_dn))
                identity_provider = identity.provider if identity else ""
                identity_identifier = identity.identifier if identity else member_dn
                raw = {attr: member_value, "member_dn": member_dn}
                if optional_uid:
                    raw["unique_member_uid"] = optional_uid
                if identity is None:
                    raw["unresolved"] = True
                    unresolved_total += 1
                    if _member_dn_in_scope(member_dn, scope):
                        unresolved_in_scope += 1
                    else:
                        raw["out_of_scope"] = True
                assignments.append(
                    _assignment(provider.name, access_name, identity_identifier, cn, raw, identity_provider)
                )
        for uid in group.get("memberuid", []):
            candidates = identity_by_uid.get(uid, [])
            identity = candidates[0] if len(candidates) == 1 else None
            identity_provider = identity.provider if identity else ""
            identity_identifier = identity.identifier if identity else uid
            raw = {"memberUid": uid, "member_uid": uid}
            if identity is None:
                raw["unresolved"] = True
                unresolved_total += 1
                unresolved_in_scope += 1
                if len(candidates) > 1:
                    raw["ambiguous"] = True
            assignments.append(
                _assignment(provider.name, access_name, identity_identifier, cn, raw, identity_provider)
            )

    if unresolved_total:
        scope["unresolved_memberships"] = unresolved_total
    if unresolved_in_scope and completeness == str(Completeness.FULL):
        completeness = str(Completeness.UNKNOWN)
        scope["completeness"] = completeness
        scope["unresolved_memberships_in_scope"] = unresolved_in_scope

    authentication_posture = _authentication_posture(provider.name, entries)
    checksum_payload = {
        "entries": entries,
        "manifest": manifest,
        "collection_errors": collection_errors,
        "trusted_export": trusted_export,
        "dn_count": len(by_dn),
        "authentication_posture": authentication_posture,
    }
    batch = ImportBatch(
        provider=provider.name,
        source_type=source_type,
        status=ImportStatus.COMPLETED,
        completeness=completeness,
        scope=scope,
        checksum=stable_checksum(checksum_payload),
    )
    from access_review_engine.domain import now_utc

    batch.completed_at = now_utc()
    return ImportResult(
        batch, provider, identities, accesses, assignments, authentication_posture=authentication_posture
    )


def _user_identity(provider: str, entry: dict[str, list[str]]) -> Identity:
    uid = _first(entry, "uid") or _first(entry, "cn") or _first(entry, "dn") or ""
    dn = _first(entry, "dn")
    entry_uuid = _first(entry, "entryuuid")
    native_id = entry_uuid or (_canonical_dn(dn) if dn else None)
    identifier = f"entry:{entry_uuid}" if entry_uuid else uid
    return Identity(
        provider=provider,
        identifier=identifier,
        native_id=native_id,
        type=IdentityType.USER_ACCOUNT,
        status=IdentityStatus.UNKNOWN,
        display_name=_first(entry, "cn") or uid,
        email=_first(entry, "mail"),
        description=_first(entry, "description"),
        metadata={
            "dn": dn,
            "uid": uid,
            "entry_uuid": entry_uuid,
            "password_policy_dn": _first(entry, "pwdpolicysubentry"),
        },
    )


def _authentication_posture(provider: str, entries: list[dict[str, list[str]]]) -> AuthenticationPosture:
    policies: list[dict[str, object]] = []
    for entry in entries:
        classes = {value.lower() for value in entry.get("objectclass", [])}
        if "pwdpolicy" not in classes and not any(key.startswith("pwd") for key in entry):
            continue
        controls = {}
        mapping = {
            "pwdminlength": "minimum_length", "pwdinhistory": "history", "pwdminage": "minimum_age_seconds",
            "pwdmaxage": "maximum_age_seconds", "pwdmaxfailure": "lockout_threshold",
            "pwdfailurecountinterval": "lockout_observation_window_seconds",
            "pwdlockoutduration": "lockout_duration_seconds",
        }
        for source, target in mapping.items():
            value = _first(entry, source)
            if value is not None:
                try:
                    controls[target] = int(value)
                except ValueError:
                    controls[target] = value
        for source, target in (("pwdlockout", "lockout_enabled"), ("pwdmustchange", "must_change"), ("pwdallowuserchange", "allow_user_change"), ("pwdsafemodify", "safe_modify")):
            value = _first(entry, source)
            if value is not None:
                controls[target] = value.lower() in {"true", "yes", "on", "1"}
        if controls:
            policies.append({"dn": _first(entry, "dn"), "controls": controls})
    if not policies:
        return AuthenticationPosture(
            provider=provider,
            controls={
                "password_policy": {"status": AuthenticationStatus.NOT_COLLECTED},
                "mfa": {"status": AuthenticationStatus.NOT_SUPPORTED},
                "federation": {"status": AuthenticationStatus.NOT_SUPPORTED},
                "tokens": {"status": AuthenticationStatus.NOT_SUPPORTED},
            },
            source="openldap_ppolicy",
            completeness=str(Completeness.UNKNOWN),
        )
    return AuthenticationPosture(
        provider=provider,
        controls={"password_policy": {"status": AuthenticationStatus.COLLECTED, "policies": policies},
                  "mfa": {"status": AuthenticationStatus.NOT_SUPPORTED},
                  "federation": {"status": AuthenticationStatus.NOT_SUPPORTED},
                  "tokens": {"status": AuthenticationStatus.NOT_SUPPORTED}},
        source="openldap_ppolicy",
        completeness=str(Completeness.UNKNOWN),
    )


def _group_identity(provider: str, entry: dict[str, list[str]]) -> Identity:
    cn = _first(entry, "cn") or _first(entry, "dn") or ""
    dn = _first(entry, "dn")
    native_id = _first(entry, "entryuuid") or (_canonical_dn(dn) if dn else None)
    identifier = f"group:{native_id}" if native_id else cn
    return Identity(
        provider=provider,
        identifier=identifier,
        native_id=native_id,
        type=IdentityType.GROUP,
        status=IdentityStatus.UNKNOWN,
        display_name=cn,
        description=_first(entry, "description"),
        metadata={"dn": dn, "cn": cn, "entry_uuid": _first(entry, "entryuuid")},
    )


def _assignment(
    provider: str,
    access_name: str,
    identity_identifier: str,
    source: str,
    raw: dict[str, object],
    identity_provider: str | None = None,
) -> AccessAssignment:
    return AccessAssignment(
        provider=provider,
        access_name=access_name,
        identity_provider=provider if identity_provider is None else identity_provider,
        identity_identifier=identity_identifier,
        origin=Origin(
            assignment_type=AssignmentType.GROUP,
            direct=True,
            inherited=False,
            source=source,
            raw=raw,
        ),
    )


def _is_user_entry(classes: set[str], entry: dict[str, list[str]]) -> bool:
    return "inetorgperson" in classes or ("posixaccount" in classes and bool(_first(entry, "uid")))


def _validate_zip_members(zf: ZipFile, max_file_bytes: int, max_ldif_file_bytes: int, max_uncompressed_bytes: int) -> None:
    total = 0
    for info in zf.infolist():
        member_limit = max_ldif_file_bytes if info.filename == "directory.ldif" else max_file_bytes
        if info.file_size > member_limit:
            raise ValueError("Archive member exceeds configured maximum size")
        total += info.file_size
        if total > max_uncompressed_bytes:
            raise ValueError("Archive uncompressed size exceeds configured maximum size")


def _validate_manifest(manifest: dict[str, object]) -> None:
    schema_version = manifest.get("schema_version")
    if schema_version is not None and schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError("manifest.yaml has unsupported schema_version")
    source_type = manifest.get("source_type")
    if source_type is not None and source_type != "openldap":
        raise ValueError("manifest.yaml has unsupported source_type")
    for key in ("completeness",):
        value = manifest.get(key)
        if value is not None and value not in SUPPORTED_COMPLETENESS:
            raise ValueError(f"manifest.yaml has unsupported {key}")
    scope = manifest.get("scope")
    if isinstance(scope, dict):
        scope_completeness = scope.get("completeness")
        if scope_completeness is not None and scope_completeness not in SUPPORTED_COMPLETENESS:
            raise ValueError("manifest.yaml scope.completeness has unsupported completeness")


def _effective_completeness(manifest: dict[str, object], collection_errors: list[dict[str, str]]) -> str:
    values = [str(manifest.get("completeness") or Completeness.UNKNOWN)]
    scope = _manifest_scope(manifest)
    if scope.get("completeness") is not None:
        values.append(str(scope["completeness"]))
    stats = manifest.get("statistics")
    if isinstance(stats, dict) and stats.get("collection_errors") not in {None, 0, "0"}:
        values.append(str(Completeness.UNKNOWN))
    if manifest.get("ldapsearch_exit_code") not in {None, 0, "0"}:
        values.append(str(Completeness.UNKNOWN))
    if str(manifest.get("limited") or "").lower() in {"1", "true", "yes", "y"}:
        values.append(str(Completeness.UNKNOWN))
    if collection_errors:
        values.append(str(Completeness.UNKNOWN))
    precedence = {str(Completeness.UNKNOWN): 0, str(Completeness.SCOPED): 1, str(Completeness.FULL): 2}
    completeness = min(values, key=lambda value: precedence.get(value, 0))
    return completeness


def _effective_scope(
    manifest: dict[str, object], completeness: str, collection_errors: list[dict[str, str]]
) -> dict[str, object]:
    scope = _manifest_scope(manifest)
    scope["completeness"] = completeness
    if collection_errors:
        scope["collection_errors"] = len(collection_errors)
    return scope


def _manifest_scope(manifest: dict[str, object]) -> dict[str, object]:
    scope = dict(manifest.get("scope")) if isinstance(manifest.get("scope"), dict) else {"type": "all"}
    for key in ("base_dn", "search_scope", "filter"):
        if key not in scope and manifest.get(key) is not None:
            scope[key] = manifest[key]
    return scope


def _member_dn_in_scope(member_dn: str, scope: dict[str, object]) -> bool:
    base_dn = str(scope.get("base_dn") or "").strip()
    if not base_dn:
        return True
    member = _canonical_dn(member_dn)
    base = _canonical_dn(base_dn)
    search_scope = str(scope.get("search_scope") or "sub").strip().lower()
    if search_scope == "base":
        return member == base
    if search_scope == "one":
        return _dn_parent(member) == base
    return member == base or member.endswith(f",{base}")


def _dn_parent(canonical_dn: str) -> str:
    parts = _split_unescaped(canonical_dn, ",")
    return ",".join(parts[1:]) if len(parts) > 1 else ""


def _read_manifest(text: str) -> dict[str, object]:
    result: dict[str, object] = {}
    stack: list[str] = []
    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("#") or ":" not in line:
            continue
        indent = len(line) - len(line.lstrip(" "))
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if indent == 0:
            stack = [key]
            result[key] = {} if value == "" else _manifest_value(value)
        elif stack:
            parent = result.setdefault(stack[0], {})
            if isinstance(parent, dict):
                parent[key] = _manifest_value(value)
    return result


def _manifest_value(value: str) -> object:
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if value.isdigit():
        return int(value)
    return value


def _read_collection_errors(text: str) -> list[dict[str, str]]:
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return []
    header = [part.strip() for part in lines[0].split(",")]
    rows = []
    for line in lines[1:]:
        values = [part.strip() for part in line.split(",")]
        rows.append(dict(zip(header, values, strict=False)))
    return rows


def _parse_ldif(text: str) -> list[dict[str, list[str]]]:
    entries: list[dict[str, list[str]]] = []
    current: dict[str, list[str]] = {}
    last_key: str | None = None
    for line in text.splitlines():
        if not line.strip():
            if current:
                _reject_change_record(current)
                entries.append(current)
                current = {}
                last_key = None
            continue
        if line.startswith((" ", "\t")) and current and last_key:
            current[last_key][-1] += line[1:]
            continue
        if line.startswith("#") or ":" not in line:
            continue
        separator = "::" if "::" in line and line.index("::") < line.index(":") + 2 else ":"
        key, value = line.split(separator, 1)
        attr = _attr_key(key)
        if attr not in USED_LDIF_ATTRIBUTES:
            last_key = None
            continue
        if separator == "::":
            try:
                decoded = b64decode(value.strip()).decode("utf-8")
            except UnicodeDecodeError as exc:
                if attr in TEXT_LDIF_ATTRIBUTES:
                    raise ValueError(f"LDIF attribute {attr} is not valid UTF-8 text") from exc
                continue
            current.setdefault(attr, []).append(decoded)
        else:
            current.setdefault(attr, []).append(value.strip())
        last_key = attr
    if current:
        _reject_change_record(current)
        entries.append(current)
    return entries


def _reject_change_record(entry: dict[str, list[str]]) -> None:
    if entry.get("changetype"):
        raise ValueError("OpenLDAP importer supports snapshot LDIF only, not LDIF change records")


def _attr_key(key: str) -> str:
    return key.split(";", 1)[0].strip().lower()


def _first(entry: dict[str, list[str]], key: str) -> str | None:
    values = entry.get(key)
    return values[0] if values else None


def _canonical_dn(value: str) -> str:
    parts = _split_unescaped(value, ",")
    canonical_parts = []
    for part in parts:
        rdns = []
        for rdn in _split_unescaped(part.strip(), "+"):
            attr, raw_value = _split_unescaped_once(rdn.strip(), "=")
            normalized_value = _normalize_dn_value(raw_value)
            rdns.append(f"{attr.strip().lower()}={normalized_value}")
        canonical_parts.append("+".join(sorted(rdns)))
    return ",".join(canonical_parts)


def _unique_member_dn_and_uid(value: str) -> tuple[str, str | None]:
    dn, uid = _split_unescaped_once(value, "#")
    if not uid:
        return value, None
    return dn, uid


def _split_unescaped(value: str, separator: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == separator:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _split_unescaped_once(value: str, separator: str) -> tuple[str, str]:
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == separator:
            return value[:index], value[index + 1 :]
    return value, ""


def _normalize_dn_value(value: str) -> str:
    text = value.strip().strip('"').lower()
    chars: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char != "\\":
            chars.append(char)
            index += 1
            continue
        escaped = text[index + 1 : index + 3]
        if len(escaped) == 2 and all(item in "0123456789abcdef" for item in escaped):
            chars.append(chr(int(escaped, 16)))
            index += 3
        elif index + 1 < len(text):
            chars.append(text[index + 1])
            index += 2
        else:
            chars.append(char)
            index += 1
    return "".join(chars)
