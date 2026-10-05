from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class UIPage:
    semantic_id: str
    label: str
    route: str
    purpose: str
    navigation_path: str
    roles: frozenset[str]


_OPERATIONAL = frozenset({"ADMIN", "OPERATOR"})
_REVIEWS = frozenset({"ADMIN", "OPERATOR", "GROUP_OWNER"})
_ACTIONS = frozenset({"ADMIN", "OPERATOR", "BUSINESS_ADMIN", "REMEDIATION_MANAGER"})

UI_CATALOG: tuple[UIPage, ...] = (
    UIPage(
        "DASHBOARD",
        "Overview",
        "/",
        "Operational overview and priorities.",
        "Overview",
        _OPERATIONAL,
    ),
    UIPage(
        "CAMPAIGNS",
        "Campaigns",
        "/campaigns",
        "Access review campaigns.",
        "Audit → Campaigns",
        _OPERATIONAL,
    ),
    UIPage(
        "CAMPAIGN_CREATE",
        "Create a campaign",
        "/campaigns/new",
        "Prepare a new campaign; navigation does not create it.",
        "Audit → Campaigns → Create a campaign",
        _OPERATIONAL,
    ),
    UIPage(
        "GOLDEN",
        "Golden Source",
        "/golden",
        "Expected access reference and its quality.",
        "Access & Reference → Golden Source",
        _OPERATIONAL,
    ),
    UIPage(
        "REVIEWS",
        "My Reviews",
        "/reviews",
        "Review items assigned or visible to the user.",
        "My Reviews",
        _REVIEWS,
    ),
    UIPage(
        "ACTIONS", "Actions", "/actions", "Read remediation follow-up.", "Audit → Actions", _ACTIONS
    ),
    UIPage(
        "SOURCES",
        "Sources & IdPs",
        "/sources",
        "Connected providers, snapshots and collection status.",
        "System → Sources & IdPs",
        _OPERATIONAL,
    ),
    UIPage(
        "REPORTS",
        "Reports",
        "/reports",
        "Authorized access-review reports.",
        "Audit → Reports",
        _OPERATIONAL,
    ),
    UIPage(
        "PERIMETERS",
        "Scopes",
        "/perimeters",
        "Organizations, information systems and their associations.",
        "Access & Reference → Scopes",
        _OPERATIONAL,
    ),
    UIPage(
        "IDENTITIES",
        "Identities",
        "/identities",
        "Observed identities and their access assignments.",
        "Access & Reference → Identities",
        _OPERATIONAL,
    ),
    UIPage(
        "ACCESSES",
        "Access",
        "/accesses",
        "Reviewable Access objects and functional model.",
        "Access & Reference → Access",
        _OPERATIONAL,
    ),
    UIPage(
        "FINDINGS",
        "Findings",
        "/findings",
        "Deterministic campaign findings.",
        "Audit → Findings",
        _OPERATIONAL,
    ),
    UIPage(
        "USERS",
        "Users & permissions",
        "/system/users",
        "EARE users and application permissions.",
        "System → Users & permissions",
        frozenset({"ADMIN"}),
    ),
)


def authorized_ui_pages(role: str) -> tuple[UIPage, ...]:
    return tuple(page for page in UI_CATALOG if role in page.roles)


def find_ui_page(role: str, *, topic: str = "", page: str = "") -> UIPage | None:
    needle = (page or topic).strip().casefold()
    if not needle:
        return None
    aliases = {
        "si": "PERIMETERS",
        "information system": "PERIMETERS",
        "système d'information": "PERIMETERS",
        "systeme d'information": "PERIMETERS",
        "create campaign": "CAMPAIGN_CREATE",
        "créer une campagne": "CAMPAIGN_CREATE",
        "creer une campagne": "CAMPAIGN_CREATE",
        "users": "USERS",
    }
    needle = aliases.get(needle, needle).casefold()
    for candidate in authorized_ui_pages(role):
        values = (
            candidate.semantic_id.casefold(),
            candidate.label.casefold(),
            candidate.route.casefold(),
            candidate.purpose.casefold(),
        )
        if needle in values or any(needle in value for value in values):
            return candidate
    return None
