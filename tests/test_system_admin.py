import sqlite3
from access_review_engine.system_admin import init_system, list_users, upsert_user, upsert_idp, list_idps

def test_system_users_and_scopes():
    c=sqlite3.connect(':memory:'); c.row_factory=sqlite3.Row; init_system(c)
    upsert_user(c, {'username':'oscar','display_name':'Oscar','role':'GROUP_OWNER','scopes':['support','logistique']})
    upsert_user(c, {'username':'louise','display_name':'Louise','role':'GROUP_OWNER','scopes':['sales']})
    users={u['username']: u for u in list_users(c)}; assert users['oscar']['scopes']==['logistique','support']; assert users['louise']['scopes']==['sales']

def test_system_idp_validation_and_storage():
    c=sqlite3.connect(':memory:'); c.row_factory=sqlite3.Row; init_system(c)
    upsert_idp(c, {'name':'Integration LDAP','kind':'LDAP','endpoint':'ldaps://ldap.example.test','enabled':True})
    assert list_idps(c)[0]['kind']=='LDAP'
