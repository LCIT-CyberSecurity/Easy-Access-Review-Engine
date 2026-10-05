from __future__ import annotations

import re
import unicodedata

from access_review_engine.chatbot.schemas import INTENTS

_SUSPICIOUS = re.compile(
    r"\bignore\b.{0,50}\b(?:instructions?|regles?|consignes?)\b|"
    r"\b(?:bypass|contourne|contourner|desactive|desactiver)\b.{0,50}"
    r"\b(?:authorization|autorisation|controles? de securite|security controls?)\b|"
    r"\b(?:montre|affiche|revele|show|reveal)\b.{0,40}\b(?:secrets?|tokens?)\b|"
    r"\b(?:montre|affiche|revele|show|reveal)\b.{0,60}"
    r"\b(?:system prompt|prompt systeme|secrets?|tokens?|donnees?)\b.{0,40}"
    r"\b(?:sans autorisation|non autorisees?|auxquelles? je n ai pas acces)\b|"
    r"\b(?:montre|affiche|show)\b.{0,100}\bauxquelles? je n ai pas acces\b|"
    r"\b(?:system prompt|prompt systeme)\b",
)
_OUT_OF_SCOPE = re.compile(
    r"\b(?:recette|recipe|crepes?|weather|meteo|joke|blague|poeme|poem|football|"
    r"translate|traduire|cuisiner|cuisine|temps|ospf|bgp)\b"
)

_GUIDANCE_TERMS = (
    "access review",
    "revue d'accès",
    "revue des accès",
    "certification",
    "recertification",
    "habilitation",
    "habilitations",
    "entitlement",
    "permission",
    "permissions",
    "access",
    "droit d acces",
    "droits d acces",
    "owner",
    "owners",
    "reviewer",
    "reviewers",
    "compte technique",
    "comptes techniques",
    "service account",
    "service accounts",
    "compte partage",
    "comptes partages",
    "shared account",
    "compte administrateur",
    "comptes administrateurs",
    "administrator account",
    "administrator accounts",
    "shared accounts",
    "compte orphelin",
    "orphan",
    "least privilege",
    "moindre privilege",
    "privileged access",
    "acces privilegie",
    "acces administrateur",
    "acces administrateurs",
    "droit administrateur",
    "droits administrateurs",
    "admin access",
    "separation des responsabilites",
    "sod",
    "iam",
    "iag",
    "identity governance",
    "access governance",
    "mfa",
    "sso",
    "functionalright",
    "functional right",
    "capability",
    "target",
    "accessassignment",
    "accessrelation",
    "rbac",
    "abac",
    "pam",
    "jit",
    "jea",
    "joiner",
    "mover",
    "leaver",
    "deprovisioning",
    "provisioning",
    "break glass",
    "session",
    "token",
    "credential",
    "passwordless",
    "federation",
    "authentication",
    "authentification",
)
_NAVIGATION_TERMS = (
    "ou",
    "where",
    "trouver",
    "gerer",
    "ouvrir",
    "open",
    "aller",
    "va",
    "page",
    "écran",
    "ecran",
    "menu",
    "localiser",
)
_USAGE_TERMS = (
    "comment",
    "how",
    "a quoi sert",
    "qu est ce que",
    "explique",
    "explain",
    "creer",
    "utiliser",
    "fonctionne",
    "difference",
)


def _normalize(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value.casefold())
    without_marks = "".join(char for char in decomposed if not unicodedata.combining(char))
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", without_marks)).strip()


def _contains(text: str, phrases: tuple[str, ...]) -> bool:
    return any(
        normalized and re.search(rf"\b{re.escape(normalized)}\b", text)
        for phrase in phrases
        if (normalized := _normalize(phrase))
    )


def classify(question: str, route: str = "/") -> str:
    text = _normalize(question)
    if _SUSPICIOUS.search(text):
        return "SUSPICIOUS"
    if _contains(text, ("dashboard", "tableau de bord")):
        return "EARE_DASHBOARD"
    explicit = _contains(
        text,
        (
            "eare",
            "campaign",
            "campaigns",
            "campagne",
            "campagnes",
            "golden",
            "review",
            "revue",
            "finding",
            "remediation",
            "source",
            "snapshot",
            "report",
            "rapport",
            "perimetre",
            "scope",
            "organisation",
            "organization",
            "systeme d information",
            "si",
            "utilisateur",
            "utilisateurs",
            "users",
            "identite",
            "identity",
            "accesses",
            "risques visibles",
            "visible risks",
            *_GUIDANCE_TERMS,
        ),
    )
    if _OUT_OF_SCOPE.search(text) and not explicit:
        return "OUT_OF_SCOPE"
    if _contains(text, ("situation", "attention", "maintenant")) and explicit:
        return "EARE_DASHBOARD"
    if _contains(text, ("ou creer", "where can i create", "creer une campagne")):
        return "EARE_USAGE"
    if _contains(text, _NAVIGATION_TERMS) and explicit:
        return "EARE_NAVIGATION"
    if (
        _contains(text, _USAGE_TERMS)
        and _contains(
            text,
            (
                "difference",
                "comment",
                "how",
                "expliquer",
                "explique",
                "organiser",
                "bonnes pratiques",
                "frequence",
                "recommande",
            ),
        )
        and _contains(text, _GUIDANCE_TERMS)
    ):
        return "EARE_ACCESS_GUIDANCE"
    if _contains(text, ("campaign", "campaigns", "campagne", "campagnes", "review campaign")):
        return "EARE_CAMPAIGN"
    if re.search(r"\bgolden\b|\bowner\b|\bexpected\b|functional model", text):
        return "EARE_GOLDEN"
    if _contains(text, ("review", "acces", "access", "unexpected", "decision")):
        return "EARE_REVIEW"
    if _contains(text, ("source", "snapshot", "synchronisation", "synchronization")):
        return "EARE_SOURCE"
    if _contains(text, ("rapport", "report", "synthese", "summary")):
        return "EARE_REPORT"
    if explicit and _contains(text, ("securite", "security", "finding", "remediation")):
        return "EARE_SECURITY_GUIDANCE"
    if _contains(text, ("risques visibles", "visible risks")):
        return "EARE_SECURITY_GUIDANCE"
    if _contains(text, _GUIDANCE_TERMS):
        return "EARE_ACCESS_GUIDANCE"
    if explicit and _contains(text, _USAGE_TERMS):
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
                r"\b(?:que|quoi|quels?|comment|explique|reste|completer|faire|traiter|priorite|aide|ca|cela)\b",
                text,
            ):
                return intent
    return "EARE_USAGE" if explicit else "OUT_OF_SCOPE"


def validate_intent(intent: str) -> str:
    return intent if intent in INTENTS else "SUSPICIOUS"
