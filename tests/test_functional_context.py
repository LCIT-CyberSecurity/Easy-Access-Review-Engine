from access_review_engine.domain import (
    Access,
    Capability,
    ExpectedAccessModel,
    FunctionalModelCompleteness,
    FunctionalRight,
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
    assert "dynamic or conditional" in context["functional_explanation"]
