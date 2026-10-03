import { describe, expect, it } from "vitest";

import { functionalRightsGroups, goldenFunctionalPresentation } from "./goldenFunctionalPresentation";

const right = (resource: string, capability: string, label = capability) => ({
  resource: { identifier: resource, display_name: resource },
  capability_id: capability,
  capability_label: label,
});

describe("goldenFunctionalPresentation", () => {
  it("renders complete expected rights and stable capability order", () => {
    const result = goldenFunctionalPresentation({
      application: "ERP",
      completeness: "complete",
      direct_functional_rights: [right("Invoices", "delete", "Delete"), right("Invoices", "read", "Read")],
      observed_functional_rights: [],
    });
    expect(result.status).toBe("Complete");
    expect(result.action).toBe("Edit rights");
    expect(result.origin).toBe("Manually defined in Golden");
    expect(result.groups).toEqual([{ resource: "Invoices", capabilities: ["Read", "Delete"] }]);
  });

  it("distinguishes undocumented, source suggestion and unresolved source data", () => {
    expect(goldenFunctionalPresentation({ application: "CRM" }).status).toBe("Not documented");
    expect(goldenFunctionalPresentation({ observed_functional_rights: [right("Invoices", "read", "Read")] }).action).toBe("Review source suggestion");
    expect(goldenFunctionalPresentation({
      observed_completeness: "not_defined",
      functional_explanation: "Authorization configuration exists, but the resulting rights cannot be fully determined statically.",
    }).status).toBe("Not statically resolved");
  });

  it("keeps inherited rights outside the direct editor summary", () => {
    const result = goldenFunctionalPresentation({
      completeness: "complete",
      direct_functional_rights: [],
      effective_functional_rights: [right("Invoices", "read", "Read")],
    });
    expect(result.groups).toEqual([]);
    expect(result.inheritedGroups).toEqual([{ resource: "Invoices", capabilities: ["Read"] }]);
  });

  it("does not repeat direct rights when effective rights contain the same entries", () => {
    const result = goldenFunctionalPresentation({
      completeness: "partial",
      direct_functional_rights: [right("Invoices", "read", "Read"), right("Suppliers", "read", "Read")],
      effective_functional_rights: [right("Invoices", "read", "Read"), right("Suppliers", "read", "Read")],
    });
    expect(result.groups).toEqual([
      { resource: "Invoices", capabilities: ["Read"] },
      { resource: "Suppliers", capabilities: ["Read"] },
    ]);
    expect(result.inheritedGroups).toEqual([]);
  });

  it("shows only the additional inherited rights", () => {
    const result = goldenFunctionalPresentation({
      completeness: "complete",
      direct_functional_rights: [right("Invoices", "read", "Read")],
      effective_functional_rights: [right("Invoices", "read", "Read"), right("Invoices", "approve", "Approve")],
    });
    expect(result.inheritedGroups).toEqual([{ resource: "Invoices", capabilities: ["Approve"] }]);
  });

  it("groups resources and sorts custom capabilities alphabetically", () => {
    expect(functionalRightsGroups([right("Suppliers", "z", "Reconcile"), right("Suppliers", "a", "Export")])).toEqual([
      { resource: "Suppliers", capabilities: ["Export", "Reconcile"] },
    ]);
  });
});
