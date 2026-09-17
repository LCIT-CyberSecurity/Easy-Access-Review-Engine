import os
import sqlite3
import subprocess

from access_review_engine.directory_auth import (
    DirectoryError,
    authenticate,
    escape_filter,
    find_account,
    parse_ldif,
    search_accounts,
    test_directory as check_directory,
    validate_directory,
)
from access_review_engine.system_admin import (
    authenticate_user,
    enabled_admins,
    init_system,
    list_users,
    reset_password,
    set_enabled,
    upsert_user,
)

CONFIG = {
    "name": "corp-directory",
    "kind": "LDAP",
    "endpoint": "ldap://ldap.example.test",
    "enabled": True,
    "settings": {"base_dn": "dc=example,dc=test", "login_attribute": "uid"},
}

ENTRIES = """dn: uid=alice,ou=people,dc=example,dc=test
uid: alice
cn: Alice
 Martin
mail: alice@example.test

dn: uid=bob,ou=people,dc=example,dc=test
uid: bob
displayName:: Qm9iIEzDqW9u
"""


def message_of(error, call, *arguments, **keywords):
    """Return the message of the expected error, so tests read the wording users will see."""
    try:
        call(*arguments, **keywords)
    except error as exc:
        return str(exc)
    raise AssertionError(f"{call.__name__} did not raise {error.__name__}")


def runner(result_map):
    """Return a fake ldapsearch runner and the list of commands it received."""
    seen = []

    def run(command, password, timeout):
        seen.append({"command": command, "password": password})
        key = "bind" if "1.1" in command else "search"
        returncode, stdout = result_map.get(key, (0, ""))
        return subprocess.CompletedProcess(command, returncode, stdout, "")

    return run, seen


def test_filter_values_are_escaped():
    assert escape_filter("a*b(c)") == r"a\2ab\28c\29"


def test_ldif_folding_and_base64_are_decoded():
    entries = parse_ldif(ENTRIES)
    assert entries[0]["cn"] == "AliceMartin"
    assert entries[0]["dn"] == "uid=alice,ou=people,dc=example,dc=test"
    assert entries[1]["displayName"] == "Bob Léon"


def test_search_returns_accounts_and_never_puts_the_password_on_the_command_line():
    run, seen = runner({"search": (0, ENTRIES)})
    accounts = search_accounts(CONFIG, "ali", runner=run)
    assert [account["login"] for account in accounts] == ["alice", "bob"]
    assert accounts[0]["display_name"] == "AliceMartin"
    assert r"(|(uid=*ali*)(cn=*ali*)(mail=*ali*))" in " ".join(seen[0]["command"])
    assert seen[0]["password"] is None


def test_search_reports_an_actionable_message_on_failure():
    run, _ = runner({"search": (49, "")})

    def failing(command, password, timeout):
        return subprocess.CompletedProcess(command, 49, "", "ldap_bind: Invalid credentials (49)")

    assert "service account credentials" in message_of(DirectoryError, search_accounts, CONFIG, "", runner=failing)


def test_ambiguous_login_never_resolves():
    run, _ = runner({"search": (0, ENTRIES)})
    assert find_account(CONFIG, "alice", runner=run) is None


def test_authentication_binds_as_the_resolved_account():
    single = ENTRIES.split("\n\n")[0] + "\n"
    run, seen = runner({"search": (0, single), "bind": (0, "")})
    account = authenticate(CONFIG, "alice", "secret", runner=run)
    assert account["dn"] == "uid=alice,ou=people,dc=example,dc=test"
    assert seen[-1]["password"] == "secret"
    assert "-D" in seen[-1]["command"]


def test_authentication_fails_on_a_rejected_bind_and_on_an_empty_password():
    single = ENTRIES.split("\n\n")[0] + "\n"
    run, _ = runner({"search": (0, single), "bind": (49, "")})
    assert authenticate(CONFIG, "alice", "wrong", runner=run) is None
    assert authenticate(CONFIG, "alice", "", runner=run) is None


def test_connection_check_reports_visible_accounts():
    run, _ = runner({"search": (0, ENTRIES)})
    assert check_directory(CONFIG, runner=run)["accounts_visible"] == 2


def test_configuration_errors_are_explicit():
    assert "base DN" in message_of(DirectoryError, validate_directory, {**CONFIG, "settings": {}})
    assert "LDAP" in message_of(DirectoryError, validate_directory, {**CONFIG, "kind": "OIDC"})
    assert "password variable" in message_of(DirectoryError, validate_directory, {**CONFIG, "settings": {**CONFIG["settings"], "bind_dn": "cn=svc", "bind_password_env": "EARE_MISSING_VARIABLE"}})


def test_service_account_password_comes_from_the_environment():
    os.environ["EARE_TEST_BIND_PASSWORD"] = "service-secret"
    try:
        config = {**CONFIG, "settings": {**CONFIG["settings"], "bind_dn": "cn=svc,dc=example,dc=test", "bind_password_env": "EARE_TEST_BIND_PASSWORD"}}
        run, seen = runner({"search": (0, ENTRIES)})
        search_accounts(config, "", runner=run)
        assert seen[0]["password"] == "service-secret"
        assert "cn=svc,dc=example,dc=test" in seen[0]["command"]
    finally:
        del os.environ["EARE_TEST_BIND_PASSWORD"]


def test_directory_users_authenticate_through_their_directory_only():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_system(conn)
    upsert_user(conn, {"username": "alice", "display_name": "Alice", "role": "OPERATOR", "auth_source": "corp-directory", "external_id": "uid=alice,ou=people,dc=example,dc=test"})
    stored = {user["username"]: user for user in list_users(conn)}["alice"]
    assert stored["auth_source"] == "corp-directory"
    assert conn.execute("SELECT password_hash FROM system_users WHERE username='alice'").fetchone()[0] is None

    def directory(source, username, external_id, password):
        return (source, username, external_id, password) == ("corp-directory", "alice", stored["external_id"], "right")

    assert authenticate_user(conn, "alice", "right", directory)["role"] == "OPERATOR"
    assert authenticate_user(conn, "alice", "wrong", directory) is None
    assert authenticate_user(conn, "alice", "right") is None


def test_directory_users_reject_a_stored_password():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_system(conn)
    assert "directory" in message_of(ValueError, upsert_user, conn, {"username": "alice", "role": "OPERATOR", "auth_source": "corp-directory", "password": "a-secure-password"})


def test_editing_a_user_keeps_a_pending_password_change():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_system(conn)
    upsert_user(conn, {"username": "bob", "role": "OPERATOR", "password": "a-secure-password", "must_change_password": True})
    upsert_user(conn, {"username": "bob", "role": "ADMIN"})
    assert {user["username"]: user for user in list_users(conn)}["bob"]["must_change_password"] is True
    upsert_user(conn, {"username": "bob", "role": "ADMIN", "must_change_password": False})
    assert {user["username"]: user for user in list_users(conn)}["bob"]["must_change_password"] is False


def test_disable_and_enable_keep_the_account_and_its_history():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_system(conn)
    upsert_user(conn, {"username": "bob", "role": "OPERATOR", "password": "a-secure-password"})
    set_enabled(conn, "bob", False)
    assert authenticate_user(conn, "bob", "a-secure-password") is None
    set_enabled(conn, "bob", True)
    assert authenticate_user(conn, "bob", "a-secure-password")["role"] == "OPERATOR"
    assert "user not found" in message_of(ValueError, set_enabled, conn, "nobody", False)


def test_reset_password_forces_a_change_and_refuses_directory_accounts():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_system(conn)
    upsert_user(conn, {"username": "bob", "role": "OPERATOR", "password": "a-secure-password"})
    reset_password(conn, "bob", "another-secure-password")
    principal = authenticate_user(conn, "bob", "another-secure-password")
    assert principal["must_change_password"] is True
    assert "12 characters" in message_of(ValueError, reset_password, conn, "bob", "short")
    upsert_user(conn, {"username": "alice", "role": "OPERATOR", "auth_source": "corp-directory", "external_id": "uid=alice"})
    assert "directory" in message_of(ValueError, reset_password, conn, "alice", "another-secure-password")


def test_enabled_admins_counts_who_could_still_sign_in():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_system(conn)
    upsert_user(conn, {"username": "root", "role": "ADMIN", "password": "a-secure-password"})
    upsert_user(conn, {"username": "second", "role": "ADMIN", "password": "a-secure-password"})
    upsert_user(conn, {"username": "suspended", "role": "ADMIN", "password": "a-secure-password", "enabled": False})
    assert enabled_admins(conn) == 2
    assert enabled_admins(conn, excluding="root") == 1
