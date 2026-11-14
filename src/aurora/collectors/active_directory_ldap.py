"""Read-only Active Directory collection over LDAP or LDAPS."""
from __future__ import annotations

import base64
import csv
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from zipfile import ZIP_DEFLATED, ZipFile



ATTRIBUTES = (
    "objectClass", "objectSid", "objectGUID", "sAMAccountName", "userPrincipalName",
    "displayName", "mail", "userAccountControl", "distinguishedName", "description",
    "primaryGroupID", "lockoutTime", "servicePrincipalName", "lastLogonTimestamp",
    "pwdLastSet", "accountExpires", "whenCreated", "name", "groupType", "managedBy",
    "member", "dNSHostName",
)

PAGE_SIZE = 1000
MAX_QUERY_OUTPUT_BYTES = 512_000_000
MAX_TOTAL_OUTPUT_BYTES = 1_000_000_000
MAX_ENTRIES = 1_000_000
MAX_MEMBER_RANGES = 10_000


class LDAPCollectionError(RuntimeError):
    """A read-only LDAP query failed or could not be proven complete."""


@dataclass
class LDAPSession:
    uri: str
    base_dn: str
    tls_mode: str
    timeout: int
    username: str
    password_file: str
    env: dict[str, str]
    password: str
    total_output_bytes: int = 0
    paged_searches: int = 0
    range_searches: int = 0

    def search(
        self,
        base_dn: str,
        scope: str,
        ldap_filter: str,
        attributes: tuple[str, ...] | list[str],
        *,
        paged: bool = False,
        size_limit: int = 0,
        range_search: bool = False,
    ) -> list[dict[str, list[str]]]:
        command = [
            "ldapsearch", "-LLL", "-o", "ldif-wrap=no", "-x", "-H", self.uri,
            "-b", base_dn, "-s", scope,
            "-o", f"nettimeout={min(max(self.timeout, 1), 60)}",
            "-l", str(self.timeout),
        ]
        if size_limit:
            command.extend(["-z", str(size_limit)])
        if paged:
            # Critical RFC 2696 paging. OpenLDAP ldapsearch follows the response cookie
            # until the server returns the final page; failing to support paging is fatal.
            command.extend(["-E", f"!pr={PAGE_SIZE}/noprompt"])
            self.paged_searches += 1
        if self.tls_mode == "starttls":
            command.append("-ZZ")
        if self.username:
            command.extend(["-D", self.username])
        if self.password_file:
            command.extend(["-y", self.password_file])
        command.extend([ldap_filter, *attributes])
        try:
            result = subprocess.run(
                command,
                env=self.env,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise LDAPCollectionError(f"LDAP search timed out after {self.timeout} seconds") from exc
        except OSError as exc:
            raise LDAPCollectionError("ldapsearch could not be executed") from exc
        output_bytes = len(result.stdout.encode("utf-8", "replace"))
        self.total_output_bytes += output_bytes
        if output_bytes > MAX_QUERY_OUTPUT_BYTES or self.total_output_bytes > MAX_TOTAL_OUTPUT_BYTES:
            raise LDAPCollectionError("LDAP response exceeded the configured output limit")
        if result.returncode:
            detail = result.stderr.strip() or "LDAP search failed"
            for secret in (self.password, self.username):
                if secret:
                    detail = detail.replace(secret, "[redacted]")
            raise LDAPCollectionError(detail[:2000])
        entries = _parse_ldif(result.stdout)
        if len(entries) > MAX_ENTRIES:
            raise LDAPCollectionError("LDAP response exceeded the object limit")
        if range_search:
            self.range_searches += 1
        return entries


def _parse_ldif(text: str) -> list[dict[str, list[str]]]:
    entries: list[dict[str, list[str]]] = []
    lines: list[str] = []
    for line in text.splitlines():
        if line.startswith(" ") and lines:
            lines[-1] += line[1:]
        else:
            lines.append(line)
    current: dict[str, list[str]] = {}
    for line in [*lines, ""]:
        if not line:
            if current:
                entries.append(current)
                current = {}
            continue
        if line.startswith("#") or ":" not in line:
            continue
        name, rest = line.split(":", 1)
        if rest.startswith(":"):
            try:
                binary = base64.b64decode(rest[1:].lstrip())
                value = base64.b64encode(binary).decode("ascii") if name.casefold() in {"objectsid", "objectguid"} else binary.decode("utf-8", "replace")
            except ValueError:
                continue
        else:
            value = rest[1:] if rest.startswith(" ") else rest
        current.setdefault(name.casefold(), []).append(value)
    return entries


def _one(entry: dict[str, list[str]], attr: str, default: str = "") -> str:
    values = entry.get(attr.casefold(), [])
    return values[0] if values else default


def _sid(entry: dict[str, list[str]]) -> str:
    encoded = entry.get("objectsid", [])
    if not encoded:
        return ""
    try:
        raw = base64.b64decode(encoded[0])
        revision, count = raw[0], raw[1]
        authority = int.from_bytes(raw[2:8], "big")
        subs = [int.from_bytes(raw[8 + i * 4:12 + i * 4], "little") for i in range(count)]
        return "S-" + "-".join(map(str, [revision, authority, *subs]))
    except (ValueError, IndexError):
        return ""


def _guid(entry: dict[str, list[str]]) -> str:
    values = entry.get("objectguid", [])
    if not values:
        return ""
    try:
        return str(uuid.UUID(bytes_le=base64.b64decode(values[0])))
    except (ValueError, AttributeError):
        return ""


def _write_csv(path: Path, columns: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _ldap_uri(server: str, tls_mode: str) -> str:
    expected_scheme = "ldaps" if tls_mode == "ldaps" else "ldap"
    value = server.strip()
    if not value:
        raise ValueError("LDAP server is required")
    if "://" not in value:
        value = f"{expected_scheme}://{value}"
    parsed = urlsplit(value)
    if parsed.scheme.casefold() != expected_scheme:
        raise ValueError(f"LDAP server URL must use {expected_scheme}:// for the selected transport")
    if not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("LDAP server must be a hostname or host:port without credentials or a path")
    return value.rstrip("/")


def _deduplicate_entries(entries: list[dict[str, list[str]]]) -> list[dict[str, list[str]]]:
    by_dn: dict[str, dict[str, list[str]]] = {}
    without_dn: list[dict[str, list[str]]] = []
    for entry in entries:
        dn = _one(entry, "dn")
        if not dn:
            without_dn.append(entry)
            continue
        current = by_dn.setdefault(dn.casefold(), {})
        for name, values in entry.items():
            target = current.setdefault(name, [])
            target.extend(value for value in values if value not in target)
    return [*by_dn.values(), *without_dn]


def _member_attribute(entry: dict[str, list[str]]) -> tuple[str | None, list[str]]:
    names = [name for name in entry if name == "member" or name.startswith("member;range=")]
    if len(names) > 1:
        raise LDAPCollectionError("LDAP returned overlapping member ranges for one group")
    if not names:
        return None, []
    name = names[0]
    return name, list(entry.get(name, []))


def _range_bounds(attribute: str) -> tuple[int, int | None]:
    match = re.fullmatch(r"member;range=(\d+)-(\d+|\*)", attribute, flags=re.IGNORECASE)
    if not match:
        raise LDAPCollectionError("LDAP returned an invalid member range")
    start = int(match.group(1))
    end = None if match.group(2) == "*" else int(match.group(2))
    if end is not None and end < start:
        raise LDAPCollectionError("LDAP returned an invalid member range")
    return start, end


def _all_group_members(entry: dict[str, list[str]], session: LDAPSession) -> list[str]:
    attribute, values = _member_attribute(entry)
    if attribute is None or attribute == "member":
        return list(dict.fromkeys(values))
    start, end = _range_bounds(attribute)
    if start != 0:
        raise LDAPCollectionError("LDAP member range did not start at zero")
    members = list(values)
    if end is None:
        return list(dict.fromkeys(members))
    expected = end - start + 1
    if len(values) != expected:
        raise LDAPCollectionError("LDAP returned an incomplete member range")
    group_dn = _one(entry, "dn")
    if not group_dn:
        raise LDAPCollectionError("LDAP group member range has no distinguished name")
    range_count = 0
    while end is not None:
        range_count += 1
        if range_count > MAX_MEMBER_RANGES:
            raise LDAPCollectionError("LDAP group exceeded the member range limit")
        next_start = end + 1
        responses = session.search(
            group_dn,
            "base",
            "(objectClass=group)",
            [f"member;range={next_start}-*"],
            range_search=True,
        )
        response = next(
            (row for row in responses if _one(row, "dn").casefold() == group_dn.casefold()),
            None,
        )
        if response is None:
            raise LDAPCollectionError("LDAP did not return the next group member range")
        attribute, page_values = _member_attribute(response)
        if attribute is None:
            raise LDAPCollectionError("LDAP omitted a requested group member range")
        if attribute == "member":
            members.extend(page_values)
            end = None
            continue
        page_start, page_end = _range_bounds(attribute)
        if page_start != next_start:
            raise LDAPCollectionError("LDAP skipped or repeated a group member range")
        members.extend(page_values)
        if page_end is None:
            end = None
        else:
            if len(page_values) != page_end - page_start + 1 or page_end < page_start:
                raise LDAPCollectionError("LDAP returned an incomplete group member range")
            end = page_end
    return list(dict.fromkeys(members))


def _filetime(value: str, *, zero_is_empty: bool = True) -> str:
    if not value:
        return ""
    ticks = int(value)
    if (zero_is_empty and ticks == 0) or ticks < 0:
        return ""
    if ticks >= 0x7FFFFFFFFFFFFFFF:
        return ""
    return (datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=ticks // 10)).isoformat().replace("+00:00", "Z")


def _generalized_time(value: str) -> str:
    if not value:
        return ""
    normalized = value.rstrip("Z")
    for format_string in ("%Y%m%d%H%M%S.%f", "%Y%m%d%H%M%S"):
        try:
            parsed = datetime.strptime(normalized, format_string).replace(tzinfo=UTC)
            return parsed.isoformat().replace("+00:00", "Z")
        except ValueError:
            pass
    raise ValueError("invalid AD generalized time")


def _domain_name(base_dn: str) -> str:
    components = []
    for part in base_dn.split(","):
        key, separator, value = part.strip().partition("=")
        if separator and key.casefold() == "dc" and value:
            components.append(value)
    return ".".join(components)


def _record_error(
    errors: list[dict[str, str]],
    object_type: str,
    identifier: str,
    sid: str,
    operation: str,
    message: str,
) -> None:
    errors.append({
        "ObjectType": object_type,
        "ObjectIdentifier": identifier[:1000],
        "ObjectSID": sid,
        "Operation": operation[:100],
        "ErrorCode": "ldap_collection_error",
        "ErrorMessage": message.replace("\r", " ").replace("\n", " ")[:2000],
    })


def _normalize(
    entries: list[dict[str, list[str]]],
    session: LDAPSession,
    errors: list[dict[str, str]],
    base_dn: str,
    extra_attributes: list[str],
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]], list[dict[str, str]], list[dict[str, str]], str, bool]:
    users: list[dict[str, str]] = []
    groups: list[dict[str, str]] = []
    computers: list[dict[str, str]] = []
    service_accounts: list[dict[str, str]] = []
    memberships: list[dict[str, str]] = []
    dn_to_principal: dict[str, dict[str, str]] = {}
    foreign_sid_by_dn: dict[str, str] = {}
    domain_sid = ""
    base_is_domain = False

    def integer(entry: dict[str, list[str]], name: str, *, default: int = 0) -> int:
        value = _one(entry, name)
        if not value:
            return default
        try:
            return int(value)
        except ValueError:
            _record_error(errors, "object", _one(entry, "dn"), _sid(entry), f"parse {name}", "AD returned an invalid integer attribute")
            return default

    def date_value(entry: dict[str, list[str]], name: str, kind: str) -> str:
        value = _one(entry, name)
        if not value:
            return ""
        try:
            return _generalized_time(value) if kind == "generalized" else _filetime(value)
        except (OverflowError, ValueError):
            _record_error(errors, "object", _one(entry, "dn"), _sid(entry), f"parse {name}", "AD returned an invalid timestamp")
            return ""

    for entry in entries:
        dn = _one(entry, "dn")
        classes = {value.casefold() for value in entry.get("objectclass", [])}
        sid = _sid(entry)
        sam = _one(entry, "samaccountname")
        if dn.casefold() == base_dn.casefold() and "domaindns" in classes:
            domain_sid = sid
            base_is_domain = True
        if "foreignsecurityprincipal" in classes:
            foreign_sid = sid
            if not foreign_sid:
                first_rdn = dn.split(",", 1)[0]
                candidate = first_rdn[3:] if first_rdn[:3].casefold() == "cn=" else ""
                if re.fullmatch(r"S-\d-(?:\d+-){1,14}\d+", candidate, re.IGNORECASE):
                    foreign_sid = candidate
            if dn and foreign_sid:
                foreign_sid_by_dn[dn.casefold()] = foreign_sid
            elif dn:
                _record_error(
                    errors,
                    "foreign_security_principal",
                    dn,
                    "",
                    "resolve foreign security principal",
                    "AD foreign security principal has no readable SID",
                )
            continue
        if not (classes & {"user", "group", "computer", "msds-managedserviceaccount", "msds-groupmanagedserviceaccount"}):
            continue
        if not sid:
            _record_error(errors, "object", dn, "", "read objectSid", "AD object has no readable or valid objectSid")
        if not dn:
            _record_error(errors, "object", sam, sid, "read distinguishedName", "AD object has no distinguishedName")
            continue
        if "group" in classes:
            if not _guid(entry):
                _record_error(errors, "group", dn, sid, "read objectGUID", "AD group has no readable or valid objectGUID")
            if not sam:
                _record_error(errors, "group", dn, sid, "normalize group", "AD group has no sAMAccountName")
                continue
            group_type = integer(entry, "grouptype") & 0xFFFFFFFF
            scope = "Global" if group_type & 2 else "DomainLocal" if group_type & 4 else "Universal" if group_type & 8 else "Unknown"
            groups.append({
                "SamAccountName": sam,
                "Name": _one(entry, "name"),
                "SID": sid,
                "ObjectGUID": _guid(entry),
                "DistinguishedName": dn,
                "Description": _one(entry, "description"),
                "GroupScope": scope,
                "GroupCategory": "Security" if group_type & 0x80000000 else "Distribution",
                "managedBy": _one(entry, "managedby"),
                **{
                    name: ";".join(entry.get(name.casefold(), []))
                    for name in extra_attributes
                },
            })
            dn_to_principal[dn.casefold()] = {"sam": sam, "sid": sid, "type": "group", "dn": dn}
        elif "computer" in classes:
            if not _guid(entry):
                _record_error(errors, "computer", dn, sid, "read objectGUID", "AD computer has no readable or valid objectGUID")
            if not sam:
                _record_error(errors, "computer", dn, sid, "normalize computer", "AD computer has no sAMAccountName")
                continue
            computer_uac = integer(entry, "useraccountcontrol")
            computers.append({
                "SamAccountName": sam, "Name": _one(entry, "name"), "SID": sid,
                "DistinguishedName": dn, "Enabled": str(not (computer_uac & 2)),
                "DNSHostName": _one(entry, "dnshostname"), "Description": _one(entry, "description"),
                "ObjectGUID": _guid(entry), "PrimaryGroupID": _one(entry, "primarygroupid"),
            })
            dn_to_principal[dn.casefold()] = {"sam": sam, "sid": sid, "type": "computer", "dn": dn}
        elif classes & {"msds-managedserviceaccount", "msds-groupmanagedserviceaccount"}:
            if not _guid(entry):
                _record_error(errors, "service_account", dn, sid, "read objectGUID", "AD service account has no readable or valid objectGUID")
            if not sam:
                _record_error(errors, "service_account", dn, sid, "normalize service account", "AD service account has no sAMAccountName")
                continue
            account_class = next(iter(classes & {"msds-managedserviceaccount", "msds-groupmanagedserviceaccount"}))
            account_uac = integer(entry, "useraccountcontrol")
            service_accounts.append({
                "SamAccountName": sam, "Name": _one(entry, "name"), "DisplayName": _one(entry, "displayname"),
                "SID": sid, "DistinguishedName": dn, "Enabled": str(not (account_uac & 2)),
                "Description": _one(entry, "description"), "ObjectClass": account_class,
                "ObjectGUID": _guid(entry), "PrimaryGroupID": _one(entry, "primarygroupid"),
                "ServicePrincipalName": ";".join(entry.get("serviceprincipalname", [])),
            })
            dn_to_principal[dn.casefold()] = {"sam": sam, "sid": sid, "type": account_class, "dn": dn}
        elif "user" in classes:
            if not _guid(entry):
                _record_error(errors, "user", dn, sid, "read objectGUID", "AD user has no readable or valid objectGUID")
            if not sam:
                _record_error(errors, "user", dn, sid, "normalize user", "AD user has no sAMAccountName")
                continue
            user_uac = integer(entry, "useraccountcontrol")
            users.append({
                "SamAccountName": sam, "UserPrincipalName": _one(entry, "userprincipalname"),
                "DisplayName": _one(entry, "displayname"), "Mail": _one(entry, "mail"),
                "Enabled": str(not (user_uac & 2)), "SID": sid, "DistinguishedName": dn,
                "Description": _one(entry, "description"), "PrimaryGroupID": _one(entry, "primarygroupid"),
                "LockedOut": str(integer(entry, "lockouttime") > 0), "ObjectGUID": _guid(entry),
                "LastLogonDate": date_value(entry, "lastlogontimestamp", "filetime"),
                "PasswordLastSet": date_value(entry, "pwdlastset", "filetime"),
                "AccountExpirationDate": date_value(entry, "accountexpires", "filetime"),
                "WhenCreated": date_value(entry, "whencreated", "generalized"),
                "ServicePrincipalName": ";".join(entry.get("serviceprincipalname", [])),
            })
            dn_to_principal[dn.casefold()] = {"sam": sam, "sid": sid, "type": "user", "dn": dn}

    groups_by_dn = {_one(entry, "dn").casefold(): entry for entry in entries if "group" in {value.casefold() for value in entry.get("objectclass", [])}}
    group_names_by_dn = {row["DistinguishedName"].casefold(): row for row in groups}
    for dn, entry in groups_by_dn.items():
        if dn not in group_names_by_dn:
            continue
        try:
            member_dns = _all_group_members(entry, session)
        except LDAPCollectionError as exc:
            _record_error(errors, "group", dn, _sid(entry), "collect group members", str(exc))
            continue
        group = group_names_by_dn[dn]
        for member_dn in member_dns:
            principal = dn_to_principal.get(member_dn.casefold(), {})
            member_sid = principal.get("sid") or foreign_sid_by_dn.get(member_dn.casefold(), "")
            if not principal and not member_sid:
                _record_error(
                    errors,
                    "member",
                    member_dn,
                    "",
                    "resolve group member",
                    "AD group member is outside the collected directory and has no resolvable SID",
                )
            member_type = principal.get("type", "foreignsecurityprincipal" if member_sid else "unknown")
            member_name = principal.get("sam") or member_sid or member_dn
            memberships.append({
                "Group": group["SamAccountName"], "GroupSID": group["SID"],
                "Member": member_name, "MemberSID": member_sid,
                "MemberType": member_type, "MemberDN": member_dn,
                "MembershipType": "direct",
            })

    groups_with_members: set[str] = set()
    try:
        member_bearing_groups = session.search(
            base_dn, "sub", "(&(objectClass=group)(member=*))",
            ["distinguishedName", "objectSid"], paged=True,
        )
        groups_with_members = {_one(row, "dn").casefold() for row in member_bearing_groups if _one(row, "dn")}
        collected_members = {
            row["GroupSID"] or row["Group"].casefold()
            for row in memberships
            if row.get("MembershipType") == "direct"
        }
        for dn in sorted(groups_with_members):
            group = group_names_by_dn.get(dn)
            if group is None:
                _record_error(errors, "group", dn, "", "verify group membership coverage", "A member-bearing group was not included in the paged object collection")
            elif not group["SID"] in collected_members and group["SamAccountName"].casefold() not in collected_members:
                _record_error(errors, "group", dn, group["SID"], "verify group membership coverage", "AD reports members but none were returned by the member attribute read")
    except LDAPCollectionError as exc:
        _record_error(errors, "group", base_dn, "", "verify group membership coverage", str(exc))

    if base_is_domain and not domain_sid:
        _record_error(errors, "domain", base_dn, "", "read domain SID", "AD domain object has no readable objectSid")

    groups_by_sid = {row["SID"]: row for row in groups if row.get("SID")}
    seen_memberships: set[tuple[str, str, str]] = set()
    deduplicated: list[dict[str, str]] = []
    for row in memberships:
        member_key = row.get("MemberSID") or row.get("MemberDN") or row.get("Member", "")
        key = (row.get("GroupSID") or row.get("Group", "").casefold(), member_key.casefold(), row.get("MembershipType", "direct"))
        if key not in seen_memberships:
            seen_memberships.add(key)
            deduplicated.append(row)
    memberships = deduplicated
    principals = [
        *((row, "user") for row in users),
        *((row, "computer") for row in computers),
        *((row, row.get("ObjectClass", "service_account")) for row in service_accounts),
    ]
    for principal, member_type in principals:
        primary_group_id = principal.get("PrimaryGroupID", "")
        sid = principal.get("SID", "")
        if not primary_group_id or not sid:
            continue
        try:
            primary_rid = str(int(primary_group_id))
        except ValueError:
            _record_error(errors, member_type, principal.get("DistinguishedName", ""), sid, "resolve primaryGroupID", "AD returned an invalid primaryGroupID")
            continue
        group_sid = sid.rsplit("-", 1)[0] + "-" + primary_rid
        group = groups_by_sid.get(group_sid)
        member_name = principal.get("SamAccountName", "")
        key = (group_sid, sid, "primary_group")
        if key not in seen_memberships:
            memberships.append({
                "Group": group.get("SamAccountName", group_sid) if group else group_sid,
                "GroupSID": group_sid, "Member": member_name, "MemberSID": sid,
                "MemberType": member_type, "MemberDN": principal.get("DistinguishedName", ""),
                "MembershipType": "primary_group",
            })
            seen_memberships.add(key)

    return users, groups, computers, service_accounts, memberships, domain_sid, base_is_domain


def _collect() -> int:
    server = os.environ["AURORA_AD_LDAP_SERVER"]
    base_dn = os.environ["AURORA_AD_LDAP_BASE_DN"].strip()
    provider = os.environ["AURORA_AD_LDAP_PROVIDER"]
    output = Path(os.environ["AURORA_AD_LDAP_OUTPUT"])
    tls_mode = os.environ.get("AURORA_AD_LDAP_TLS_MODE")
    if tls_mode is None:
        tls_mode = "ldaps" if os.environ.get("AURORA_AD_LDAP_USE_TLS", "1") == "1" else "none"
    if tls_mode not in {"none", "starttls", "ldaps"}:
        raise ValueError("LDAP TLS mode must be none, starttls or ldaps")
    if not base_dn:
        raise ValueError("Active Directory LDAP base DN is required")
    check_only = os.environ.get("AURORA_AD_LDAP_CHECK_ONLY") == "1"
    allow_partial = os.environ.get("AURORA_AD_LDAP_ALLOW_PARTIAL") == "1"
    timeout = max(1, min(int(os.environ.get("AURORA_AD_LDAP_TIMEOUT_SECONDS", "300")), 3600))
    username = os.environ.get("AURORA_LDAP_USERNAME", "").strip()
    password = os.environ.get("AURORA_LDAP_PASSWORD", "")
    password_file_env = os.environ.get("AURORA_LDAP_PASSWORD_FILE", "")
    if not password and password_file_env:
        try:
            password = Path(password_file_env).read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as exc:
            raise ValueError("LDAP password file could not be read") from exc
    if not username or not password:
        raise ValueError("Active Directory LDAP requires a bind username and password")
    extra_attributes = [value.strip() for value in os.environ.get("AURORA_AD_LDAP_EXTRA_ATTRIBUTES", "").split(",") if value.strip()]
    for attribute in extra_attributes:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,63}", attribute) or re.search(r"password|token|secret|privatekey|credential", attribute, re.IGNORECASE):
            raise ValueError("Invalid or sensitive additional LDAP attribute")
    uri = _ldap_uri(server, tls_mode)
    ca_cert = os.environ.get("AURORA_AD_LDAP_CA_CERT", "")
    ldap_env = os.environ.copy()
    if tls_mode != "none":
        ldap_env["LDAPTLS_REQCERT"] = "demand"
        ldap_env["LDAPTLS_REQSAN"] = "demand"
        if ca_cert:
            if not Path(ca_cert).is_file():
                raise ValueError("Configured LDAP CA certificate file is not readable")
            ldap_env["LDAPTLS_CACERT"] = ca_cert

    fd, password_path = tempfile.mkstemp(prefix="aurora-ad-ldap-password-")
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(password)
    session = LDAPSession(uri, base_dn, tls_mode, timeout, username, password_path, ldap_env, password)
    errors: list[dict[str, str]] = []
    try:
        if check_only:
            entries = session.search(base_dn, "sub", "(&(objectClass=group)(member=*))", ["distinguishedName", "objectSid", "member"], paged=True)
            if not entries or not _one(entries[0], "dn"):
                raise LDAPCollectionError("LDAP bind succeeded but no readable AD group membership was returned")
            print("Active Directory LDAP read-only check succeeded")
            return 0

        ldap_filter = (
            "(|(objectCategory=person)(objectClass=group)(objectClass=computer)"
            "(objectClass=msDS-ManagedServiceAccount)"
            "(objectClass=msDS-GroupManagedServiceAccount)"
            "(objectClass=foreignSecurityPrincipal)(objectClass=domainDNS))"
        )
        try:
            entries = _deduplicate_entries(session.search(
                base_dn, "sub", ldap_filter, list(dict.fromkeys((*ATTRIBUTES, *extra_attributes))), paged=True
            ))
        except LDAPCollectionError as exc:
            if not allow_partial:
                raise
            _record_error(errors, "directory", base_dn, "", "collect paged directory objects", str(exc))
            entries = []

        users, groups, computers, service_accounts, memberships, domain_sid, base_is_domain = _normalize(
            entries, session, errors, base_dn, extra_attributes
        )
        if not entries and not errors:
            raise LDAPCollectionError("LDAP search returned no directory entries")
        if errors and not allow_partial:
            first_error = errors[0]
            raise LDAPCollectionError(first_error["ErrorMessage"])

        completeness = "unknown" if errors else ("full" if base_is_domain else "scoped")
        scope_type = "all" if base_is_domain else "base_dn"
        domain = _domain_name(base_dn)
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="aurora-ad-ldap-export-") as temp_dir:
            temp = Path(temp_dir)
            _write_csv(temp / "users.csv", ["SamAccountName", "UserPrincipalName", "DisplayName", "Mail", "Enabled", "SID", "DistinguishedName", "Description", "PrimaryGroupID", "LockedOut", "ObjectGUID", "LastLogonDate", "PasswordLastSet", "AccountExpirationDate", "WhenCreated", "ServicePrincipalName"], users)
            group_columns = list(dict.fromkeys(["SamAccountName", "Name", "SID", "ObjectGUID", "DistinguishedName", "Description", "GroupScope", "GroupCategory", "managedBy", *extra_attributes]))
            _write_csv(temp / "groups.csv", group_columns, groups)
            _write_csv(temp / "computers.csv", ["SamAccountName", "Name", "SID", "DistinguishedName", "Enabled", "DNSHostName", "Description", "ObjectGUID", "PrimaryGroupID"], computers)
            _write_csv(temp / "service_accounts.csv", ["SamAccountName", "Name", "DisplayName", "SID", "DistinguishedName", "Enabled", "Description", "ObjectClass", "ObjectGUID", "PrimaryGroupID", "ServicePrincipalName"], service_accounts)
            _write_csv(temp / "memberships.csv", ["Group", "GroupSID", "Member", "MemberSID", "MemberType", "MemberDN", "MembershipType"], memberships)
            files = ["manifest.yaml", "users.csv", "groups.csv", "memberships.csv", "computers.csv", "service_accounts.csv"]
            if errors:
                _write_csv(temp / "collection-errors.csv", ["ObjectType", "ObjectIdentifier", "ObjectSID", "Operation", "ErrorCode", "ErrorMessage"], errors)
                files.append("collection-errors.csv")
            manifest_text = "\n".join([
                "schema_version: 1", "source_type: active_directory", f"provider: {json.dumps(provider)}",
                f"domain: {json.dumps(domain)}", f"domain_sid: {json.dumps(domain_sid)}",
                f"completeness: {completeness}", "scope:", f"  type: {scope_type}",
                f"  base_dn: {json.dumps(base_dn)}", f"  completeness: {completeness}", "  source: ldap",
                "statistics:", f"  users: {len(users)}", f"  groups: {len(groups)}",
                f"  service_accounts: {len(service_accounts)}", f"  computers: {len(computers)}",
                f"  memberships: {len(memberships)}", f"  membership_rows: {len(memberships)}",
                f"  collection_errors: {len(errors)}",
                f"  paged_searches: {session.paged_searches}", f"  range_searches: {session.range_searches}", "",
            ])
            (temp / "manifest.yaml").write_text(manifest_text, encoding="utf-8")
            with ZipFile(output, "w", ZIP_DEFLATED) as archive:
                for name in files:
                    archive.write(temp / name, name)
        print(f"Collected {len(users)} users, {len(groups)} groups, {len(computers)} computers, {len(service_accounts)} service accounts and {len(memberships)} memberships ({completeness})")
        if errors:
            print(f"Collection diagnostics: {len(errors)}", file=sys.stderr)
        return 0
    finally:
        Path(password_path).unlink(missing_ok=True)


def main() -> int:
    try:
        return _collect()
    except (KeyError, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"Active Directory LDAP collection failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
