import os
import sqlite3
import pytest
from access_review_engine.system_admin import authenticate_user, ensure_bootstrap_user, init_system, list_users, upsert_user, upsert_idp, list_idps

def test_system_users_and_scopes():
    c=sqlite3.connect(':memory:'); c.row_factory=sqlite3.Row; init_system(c)
    upsert_user(c, {'username':'oscar','display_name':'Oscar','role':'GROUP_OWNER','scopes':['support','logistique']})
    upsert_user(c, {'username':'louise','display_name':'Louise','role':'GROUP_OWNER','scopes':['sales']})
    users={u['username']: u for u in list_users(c)}; assert users['oscar']['scopes']==['logistique','support']; assert users['louise']['scopes']==['sales']

def test_system_idp_validation_and_storage():
    c=sqlite3.connect(':memory:'); c.row_factory=sqlite3.Row; init_system(c)
    upsert_idp(c, {'name':'Integration LDAP','kind':'LDAP','endpoint':'ldaps://ldap.example.test','enabled':True})
    assert list_idps(c)[0]['kind']=='LDAP'


def test_system_user_password_is_hashed_and_authentication_is_explicit():
    c=sqlite3.connect(':memory:'); c.row_factory=sqlite3.Row; init_system(c)
    upsert_user(c, {'username':'admin','role':'ADMIN','password':'a-secure-password'})
    assert authenticate_user(c, 'admin', 'a-secure-password')['role'] == 'ADMIN'
    assert authenticate_user(c, 'admin', 'wrong-password') is None
    assert c.execute("SELECT password_hash FROM system_users WHERE username='admin'").fetchone()[0] != 'a-secure-password'


def test_default_bootstrap_creates_hashed_admin_admin():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    init_system(c)
    old_username = os.environ.pop("EARE_ADMIN_USERNAME", None)
    old_password = os.environ.pop("EARE_ADMIN_PASSWORD", None)
    try:
        ensure_bootstrap_user(c)
    finally:
        if old_username is not None: os.environ["EARE_ADMIN_USERNAME"] = old_username
        if old_password is not None: os.environ["EARE_ADMIN_PASSWORD"] = old_password
    assert authenticate_user(c, "admin", "admin")["role"] == "ADMIN"
    assert c.execute("SELECT password_hash FROM system_users").fetchone()[0] != "admin"


def test_bootstrap_environment_overrides_and_normal_policy():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    init_system(c)
    old_username = os.environ.get("EARE_ADMIN_USERNAME")
    old_password = os.environ.get("EARE_ADMIN_PASSWORD")
    os.environ["EARE_ADMIN_USERNAME"] = "custom"
    os.environ["EARE_ADMIN_PASSWORD"] = "custom-password-long-enough"
    try:
        ensure_bootstrap_user(c)
    finally:
        if old_username is None: os.environ.pop("EARE_ADMIN_USERNAME", None)
        else: os.environ["EARE_ADMIN_USERNAME"] = old_username
        if old_password is None: os.environ.pop("EARE_ADMIN_PASSWORD", None)
        else: os.environ["EARE_ADMIN_PASSWORD"] = old_password
    assert authenticate_user(c, "custom", "custom-password-long-enough") is not None
    with pytest.raises(ValueError):
        upsert_user(c, {"username": "ordinary", "role": "OPERATOR", "password": "admin"})
