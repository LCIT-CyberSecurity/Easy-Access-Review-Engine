from access_review_engine.domain import (
    Access,
    AccessRelation,
    Capability,
    ExpectedAccessModel,
    FunctionalModelCompleteness,
    FunctionalRight,
    Origin,
    Provenance,
    Target,
)
from access_review_engine.functional_context import functional_context


def test_functional_context_uses_capability_labels_without_rewriting_ids() -> None:
    access = Access("access:foo", "keycloak")
    model = ExpectedAccessModel(
        "keycloak",
        "access:foo",
        FunctionalModelCompleteness.COMPLETE,
        (
            FunctionalRight(
                Target(
                    service={"identifier": "Keycloak"},
                    component={"identifier": "client-1", "display_name": "Payments"},
                    resource={"identifier": "resource-1", "display_name": "Invoices"},
                ),
                "keycloak_scope_abc123",
                Provenance.MAPPED,
                "native:scope-1",
            ),
        ),
    )

    context = functional_context(
        access,
        [access],
        [],
        [model],
        capabilities=[Capability("keycloak_scope_abc123", "invoice.validate", "Native scope")],
    )

    right = context["functional_rights"][0]
    assert right["capability"] == "keycloak_scope_abc123"
    assert right["capability_label"] == "invoice.validate"
    assert context["application"] == "Payments"


def test_functional_context_explains_model_without_statical_rights() -> None:
    access = Access("access:dynamic", "keycloak")
    context = functional_context(
        access,
        [access],
        [],
        [ExpectedAccessModel("keycloak", "access:dynamic", "not_defined", ())],
    )

    assert context["functional_rights"] == []
    assert context["functional_completeness"] == "not_defined"
    assert "cannot be fully determined statically" in context["functional_explanation"]


def test_functional_context_aggregates_complete_and_partial_children_as_partial() -> None:
    root = Access("root", "keycloak")
    complete = Access("complete", "keycloak")
    partial = Access("partial", "keycloak")
    relations = [
        AccessRelation(
            "keycloak", "root", "keycloak", "complete", "grants", Origin("test", True, False)
        ),
        AccessRelation(
            "keycloak", "root", "keycloak", "partial", "grants", Origin("test", True, False)
        ),
    ]
    models = [
        ExpectedAccessModel("keycloak", "complete", "complete", ()),
        ExpectedAccessModel("keycloak", "partial", "partial", ()),
    ]

    context = functional_context(root, [root, complete, partial], relations, models)

    assert context["functional_completeness"] == "partial"
    assert "conditional" in context["functional_explanation"]


def test_functional_context_aggregates_complete_and_not_defined_as_partial() -> None:
    root = Access("root", "keycloak")
    complete = Access("complete", "keycloak")
    unknown = Access("unknown", "keycloak")
    relations = [
        AccessRelation(
            "keycloak", "root", "keycloak", "complete", "grants", Origin("test", True, False)
        ),
        AccessRelation(
            "keycloak", "root", "keycloak", "unknown", "grants", Origin("test", True, False)
        ),
    ]
    models = [
        ExpectedAccessModel("keycloak", "complete", "complete", ()),
        ExpectedAccessModel("keycloak", "unknown", "not_defined", ()),
    ]

    context = functional_context(root, [root, complete, unknown], relations, models)

    assert context["functional_completeness"] == "partial"


def test_functional_context_aggregates_partial_and_not_defined_as_partial() -> None:
    root = Access("root", "keycloak")
    partial = Access("partial", "keycloak")
    unknown = Access("unknown", "keycloak")
    relations = [
        AccessRelation(
            "keycloak", "root", "keycloak", "partial", "grants", Origin("test", True, False)
        ),
        AccessRelation(
            "keycloak", "root", "keycloak", "unknown", "grants", Origin("test", True, False)
        ),
    ]
    models = [
        ExpectedAccessModel("keycloak", "partial", "partial", ()),
        ExpectedAccessModel("keycloak", "unknown", "not_defined", ()),
    ]

    context = functional_context(root, [root, partial, unknown], relations, models)

    assert context["functional_completeness"] == "partial"


def test_functional_context_only_not_defined_explains_existing_unknown_configuration() -> None:
    root = Access("root", "keycloak")
    child = Access("child", "keycloak")
    relation = AccessRelation(
        "keycloak", "root", "keycloak", "child", "grants", Origin("test", True, False)
    )
    model = ExpectedAccessModel("keycloak", "child", "not_defined", ())

    context = functional_context(root, [root, child], [relation], [model])

    assert context["functional_completeness"] == "not_defined"
    assert "configuration exists" in context["functional_explanation"]
