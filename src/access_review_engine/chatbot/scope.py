from __future__ import annotations

import re

from access_review_engine.chatbot.schemas import INTENTS

_SUSPICIOUS = re.compile(
    r"ignore\s+(?:all\s+|toutes?\s+)?(?:previous|prior|your|tes|vos|mes)?\s*instructions?|"
    r"ignore\s+(?:all\s+)?(?:previous|prior|your|tes|vos|mes)\s+(?:r[eè]gles?|consignes?)|"
    r"list\s+(?:all|every)\s+(?:users?|campaigns?|passwords?)|"
    r"liste\s+tous?\s+les\s+(?:utilisateurs?|campagnes?|mots?\s+de\s+passe)|"
    r"show\s+all\s+(?:secrets?|tokens?)",
    re.IGNORECASE,
)
_OUT_OF_SCOPE = re.compile(
    r"(?:recette|recipe|cr[êe]pes?|weather|m[ée]t[ée]o|joke|poem|football|translate)",
    re.IGNORECASE,
)

_GUIDANCE_TERMS = (
    "access review", "revue d'accès", "revue des accès", "certification", "recertification",
    "habilitation", "entitlement", "permission", "access", "droit d'accès", "owner",
    "reviewer", "reviewers", "compte technique", "service account", "compte partagé",
    "shared account", "compte orphelin", "orphan", "least privilege", "moindre privilège",
    "privileged access", "accès privilégié", "séparation des responsabilités", "sod", "iam",
    "iag", "identity governance", "access governance", "mfa", "sso", "functionalright",
    "functional right", "capability", "target", "accessassignment", "accessrelation",
)
_NAVIGATION_TERMS = (
    "où", "ou ", "where", "trouver", "gérer", "gerer", "ouvrir", "open", "aller", "va ",
    "page", "écran", "ecran", "menu", "localiser",
)
_USAGE_TERMS = (
    "comment", "how", "à quoi sert", "a quoi sert", "qu'est-ce que", "qu est ce que",
    "explique", "explain", "créer", "creer", "utiliser", "fonctionne", "différence", "difference",
)


def classify(question: str, route: str = "/") -> str:
    if _SUSPICIOUS.search(question):
        return "SUSPICIOUS"
    if _OUT_OF_SCOPE.search(question):
        return "OUT_OF_SCOPE"
    text = question.casefold()
    explicit = any(word in text for word in (
        "eare", "campaign", "campagne", "golden", "review", "revue", "finding",
        "remediation", "remédiation", "source", "snapshot", "report", "rapport",
        "périmètre", "perimetre", "scope", "organisation", "organization", "système d'information",
        "systeme d'information", "si ", "utilisateur", "users", "identité", "identite",
        "findings", "accesses", *_GUIDANCE_TERMS,
    ))
    if any(word in text for word in ("dashboard", "situation", "attention", "maintenant")):
        return "EARE_DASHBOARD"
    if any(word in text for word in ("où créer", "ou creer", "where can i create", "créer une campagne", "creer une campagne")):
        return "EARE_USAGE"
    if any(word in text for word in _USAGE_TERMS) and any(
        word in text for word in ("différence", "difference", "comment", "how", "expliquer", "explique", "organiser", "bonnes pratiques", "fréquence", "frequence")
    ) and any(word in text for word in _GUIDANCE_TERMS):
        return "EARE_ACCESS_GUIDANCE"
    if any(word in text for word in ("campaign", "campagne", "review campaign")):
        return "EARE_CAMPAIGN"
    if re.search(r"\bgolden\b|\bowner\b|\bexpected\b|functional model", text):
        return "EARE_GOLDEN"
    if any(word in text for word in ("review", "accès", "access", "unexpected", "décision")):
        return "EARE_REVIEW"
    if any(word in text for word in ("source", "snapshot", "synchron")):
        return "EARE_SOURCE"
    if any(word in text for word in ("rapport", "report", "synthèse", "summary")):
        return "EARE_REPORT"
    if any(word in text for word in _NAVIGATION_TERMS) and explicit:
        return "EARE_NAVIGATION"
    if any(word in text for word in ("sécurité", "security", "finding", "remediation")):
        return "EARE_SECURITY_GUIDANCE"
    if any(word in text for word in _GUIDANCE_TERMS):
        return "EARE_ACCESS_GUIDANCE"
    if explicit and any(word in text for word in _USAGE_TERMS):
        return "EARE_USAGE"
    normalized_route = route.split("?", 1)[0].rstrip("/") or "/"
    contextual_routes = {
        "/": "EARE_DASHBOARD",
        "/dashboard": "EARE_DASHBOARD",
        "/campaigns": "EARE_CAMPAIGN",
        "/reviews": "EARE_REVIEW",
        "/golden": "EARE_GOLDEN",
        "/sources": "EARE_SOURCE",
        "/reports": "EARE_REPORT",
    }
    for prefix, intent in contextual_routes.items():
        if normalized_route == prefix or normalized_route.startswith(prefix + "/"):
            if not explicit and re.search(
                r"\b(?:que|quoi|comment|explique|reste|compl(?:é|e)ter|faire|aide|ça|cela)\b",
                text,
            ):
                return intent
    return "EARE_USAGE" if explicit else "OUT_OF_SCOPE"


def validate_intent(intent: str) -> str:
    return intent if intent in INTENTS else "SUSPICIOUS"
