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
from pathlib import Path
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile



ATTRIBUTES = (
    "objectClass", "objectSid", "objectGUID", "sAMAccountName", "userPrincipalName",
    "displayName", "mail", "userAccountControl", "distinguishedName", "description",
    "primaryGroupID", "lockoutTime", "servicePrincipalName", "lastLogonTimestamp",
    "pwdLastSet", "accountExpires", "whenCreated", "name", "groupType", "managedBy",
    "member", "dNSHostName",
)


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


def _collect() -> int:
    server = os.environ["AURORA_AD_LDAP_SERVER"]
    base_dn = os.environ["AURORA_AD_LDAP_BASE_DN"]
    provider = os.environ["AURORA_AD_LDAP_PROVIDER"]
    output = Path(os.environ["AURORA_AD_LDAP_OUTPUT"])
    tls_mode = os.environ.get("AURORA_AD_LDAP_TLS_MODE")
    if tls_mode is None:
        tls_mode = "ldaps" if os.environ.get("AURORA_AD_LDAP_USE_TLS", "1") == "1" else "none"
    if tls_mode not in {"none", "starttls", "ldaps"}:
        raise ValueError("LDAP TLS mode must be none, starttls or ldaps")
    check_only = os.environ.get("AURORA_AD_LDAP_CHECK_ONLY") == "1"
    timeout = max(1, min(int(os.environ.get("AURORA_AD_LDAP_TIMEOUT_SECONDS", "300")), 3600))
    username = os.environ.get("AURORA_LDAP_USERNAME", "")
    password = os.environ.get("AURORA_LDAP_PASSWORD", "")
    extra_attributes = [value.strip() for value in os.environ.get("AURORA_AD_LDAP_EXTRA_ATTRIBUTES", "").split(",") if value.strip()]
    for attribute in extra_attributes:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,63}", attribute) or re.search(r"password|token|secret|privatekey|credential", attribute, re.IGNORECASE):
            raise ValueError("Invalid or sensitive additional LDAP attribute")
    server = server.strip()
    use_tls = tls_mode != "none"
    if server.startswith(("ldap://", "ldaps://")):
        uri = server.rstrip("/")
        scheme_matches = uri.startswith("ldaps://") if tls_mode == "ldaps" else uri.startswith("ldap://")
        if not scheme_matches:
            expected = "ldaps://" if tls_mode == "ldaps" else "ldap://"
            raise ValueError(f"LDAP server URL must use {expected} for the selected transport")
    else:
        uri = ("ldaps://" if tls_mode == "ldaps" else "ldap://") + server
    args = ["ldapsearch", "-LLL", "-o", "ldif-wrap=no", "-x", "-H", uri,
            "-b", base_dn, "-s", "sub", "-E", "pr=1000/noprompt"]
    ldap_env = os.environ.copy()
    if username:
        args.extend(["-D", username])
    if tls_mode == "starttls":
        args.append("-ZZ")
    password_path: str | None = None
    try:
        ca_cert = os.environ.get("AURORA_AD_LDAP_CA_CERT", "")
        if use_tls:
            ldap_env["LDAPTLS_REQCERT"] = "demand"
            ldap_env["LDAPTLS_REQSAN"] = "demand"
            if ca_cert:
                ldap_env["LDAPTLS_CACERT"] = ca_cert
        if password:
            fd, password_path = tempfile.mkstemp(prefix="aurora-ad-ldap-password-")
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(password)
            args.extend(["-y", password_path])
        if check_only:
            args.extend(["-s", "base", "(objectClass=*)", "defaultNamingContext"])
        else:
            args.extend([
                "(|(objectCategory=person)(objectClass=group)(objectClass=computer)"
                "(objectClass=msDS-ManagedServiceAccount)"
                "(objectClass=msDS-GroupManagedServiceAccount))",
                *dict.fromkeys((*ATTRIBUTES, *extra_attributes)),
            ])
        result = subprocess.run(args, env=ldap_env, capture_output=True, text=True, timeout=timeout, check=False)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "LDAP query failed")
    finally:
        if password_path:
            Path(password_path).unlink(missing_ok=True)
    if check_only:
        print("Active Directory LDAP check succeeded")
        return 0

    entries = _parse_ldif(result.stdout)
    users: list[dict[str, str]] = []
    groups: list[dict[str, str]] = []
    computers: list[dict[str, str]] = []
    service_accounts: list[dict[str, str]] = []
    memberships: list[dict[str, str]] = []
    dn_to_principal: dict[str, dict[str, str]] = {}
    domain_sid = ""
    domain = base_dn
    for part in base_dn.split(","):
        if part.strip().lower().startswith("dc="):
            domain = domain.replace(part, part.split("=", 1)[1])
    domain = domain.replace(",", ".")
    for entry in entries:
        dn = _one(entry, "dn")
        classes = {value.casefold() for value in entry.get("objectclass", [])}
        sam = _one(entry, "samaccountname")
        sid = _sid(entry)
        if dn.casefold() == base_dn.casefold():
            domain_sid = sid
        if "group" in classes:
            group_type = int(_one(entry, "grouptype", "0") or "0") & 0xFFFFFFFF
            scope = "Global" if group_type & 2 else "DomainLocal" if group_type & 4 else "Universal" if group_type & 8 else "Unknown"
            row = {"SamAccountName": sam, "Name": _one(entry, "name"), "SID": sid,
                   "DistinguishedName": dn, "Description": _one(entry, "description"),
                   "GroupScope": scope, "GroupCategory": "Security" if group_type & 0x80000000 else "Distribution",
                   "managedBy": _one(entry, "managedby")}
            groups.append(row)
            dn_to_principal[dn.casefold()] = {"sam": sam, "sid": sid, "type": "group", "dn": dn}
        elif "computer" in classes:
            row = {"SamAccountName": sam, "Name": _one(entry, "name"), "SID": sid,
                   "DistinguishedName": dn, "Enabled": str(not (int(_one(entry, "useraccountcontrol", "0") or "0") & 2)),
                   "DNSHostName": _one(entry, "dnshostname"), "Description": _one(entry, "description"),
                   "ObjectGUID": _guid(entry), "PrimaryGroupID": _one(entry, "primarygroupid")}
            computers.append(row)
            dn_to_principal[dn.casefold()] = {"sam": sam, "sid": sid, "type": "computer", "dn": dn}
        elif classes & {"msds-managedserviceaccount", "msds-groupmanagedserviceaccount"}:
            row = {"SamAccountName": sam, "Name": _one(entry, "name"), "DisplayName": _one(entry, "displayname"),
                   "SID": sid, "DistinguishedName": dn, "Enabled": str(not (int(_one(entry, "useraccountcontrol", "0") or "0") & 2)),
                   "Description": _one(entry, "description"), "ObjectClass": next(iter(classes & {"msds-managedserviceaccount", "msds-groupmanagedserviceaccount"})),
                   "ObjectGUID": _guid(entry), "PrimaryGroupID": _one(entry, "primarygroupid"),
                   "ServicePrincipalName": ";".join(entry.get("serviceprincipalname", []))}
            service_accounts.append(row)
            dn_to_principal[dn.casefold()] = {"sam": sam, "sid": sid, "type": "service_account", "dn": dn}
        elif "user" in classes and sam:
            row = {"SamAccountName": sam, "UserPrincipalName": _one(entry, "userprincipalname"),
                   "DisplayName": _one(entry, "displayname"), "Mail": _one(entry, "mail"),
                   "Enabled": str(not (int(_one(entry, "useraccountcontrol", "0") or "0") & 2)),
                   "SID": sid, "DistinguishedName": dn, "Description": _one(entry, "description"),
                   "PrimaryGroupID": _one(entry, "primarygroupid"), "LockedOut": str(int(_one(entry, "lockouttime", "0") or "0") > 0),
                   "ObjectGUID": _guid(entry), "LastLogonDate": _one(entry, "lastlogontimestamp"),
                   "PasswordLastSet": _one(entry, "pwdlastset"), "AccountExpirationDate": _one(entry, "accountexpires"),
                   "WhenCreated": _one(entry, "whencreated"), "ServicePrincipalName": ";".join(entry.get("serviceprincipalname", []))}
            users.append(row)
            dn_to_principal[dn.casefold()] = {"sam": sam, "sid": sid, "type": "user", "dn": dn}

    for entry in entries:
        if "group" not in {value.casefold() for value in entry.get("objectclass", [])}:
            continue
        group_name = _one(entry, "samaccountname")
        group_sid = _sid(entry)
        for member_dn in entry.get("member", []):
            member = dn_to_principal.get(member_dn.casefold(), {})
            memberships.append({"Group": group_name, "GroupSID": group_sid, "Member": member.get("sam", member_dn),
                                "MemberSID": member.get("sid", ""), "MemberType": member.get("type", "unknown"),
                                "MemberDN": member_dn, "MembershipType": "direct"})

    groups_by_sid = {row["SID"]: row for row in groups if row.get("SID")}
    seen_memberships = {(row["GroupSID"], row["MemberSID"]) for row in memberships if row.get("GroupSID") and row.get("MemberSID")}
    for principal in [*users, *computers, *service_accounts]:
        primary_group_id = principal.get("PrimaryGroupID", "")
        sid = principal.get("SID", "")
        if not primary_group_id or not sid:
            continue
        group_sid = sid.rsplit("-", 1)[0] + "-" + primary_group_id
        group = groups_by_sid.get(group_sid)
        key = (group_sid, sid)
        if group and key not in seen_memberships:
            memberships.append({"Group": group.get("SamAccountName", ""), "GroupSID": group_sid,
                                "Member": principal.get("SamAccountName", ""), "MemberSID": sid,
                                "MemberType": "user", "MemberDN": principal.get("DistinguishedName", ""),
                                "MembershipType": "primary_group"})
            seen_memberships.add(key)

    if not users and not groups and not computers and not service_accounts:
        raise RuntimeError("LDAP succeeded but returned no Active Directory objects")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="aurora-ad-ldap-export-") as temp_dir:
        temp = Path(temp_dir)
        _write_csv(temp / "users.csv", ["SamAccountName", "UserPrincipalName", "DisplayName", "Mail", "Enabled", "SID", "DistinguishedName", "Description", "PrimaryGroupID", "LockedOut", "ObjectGUID", "LastLogonDate", "PasswordLastSet", "AccountExpirationDate", "WhenCreated", "ServicePrincipalName"], users)
        _write_csv(temp / "groups.csv", ["SamAccountName", "Name", "SID", "DistinguishedName", "Description", "GroupScope", "GroupCategory", "managedBy"], groups)
        _write_csv(temp / "computers.csv", ["SamAccountName", "Name", "SID", "DistinguishedName", "Enabled", "DNSHostName", "Description", "ObjectGUID", "PrimaryGroupID"], computers)
        _write_csv(temp / "service_accounts.csv", ["SamAccountName", "Name", "DisplayName", "SID", "DistinguishedName", "Enabled", "Description", "ObjectClass", "ObjectGUID", "PrimaryGroupID", "ServicePrincipalName"], service_accounts)
        _write_csv(temp / "memberships.csv", ["Group", "GroupSID", "Member", "MemberSID", "MemberType", "MemberDN", "MembershipType"], memberships)
        manifest_text = "\n".join([
            "schema_version: 1", "source_type: active_directory", f"provider: {json.dumps(provider)}",
            f"domain: {json.dumps(domain)}", f"domain_sid: {json.dumps(domain_sid)}", "completeness: full",
            "scope:", "  type: all", "  completeness: full", "  source: ldap", "statistics:",
            f"  users: {len(users)}", f"  groups: {len(groups)}", f"  service_accounts: {len(service_accounts)}",
            f"  computers: {len(computers)}", f"  memberships: {len(memberships)}", "  collection_errors: 0", "",
        ])
        (temp / "manifest.yaml").write_text(manifest_text, encoding="utf-8")
        with ZipFile(output, "w", ZIP_DEFLATED) as archive:
            for name in ("manifest.yaml", "users.csv", "groups.csv", "memberships.csv", "computers.csv", "service_accounts.csv"):
                archive.write(temp / name, name)
    print(f"Collected {len(users)} users, {len(groups)} groups and {len(memberships)} memberships")
    return 0


def main() -> int:
    try:
        return _collect()
    except (KeyError, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"Active Directory LDAP collection failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
