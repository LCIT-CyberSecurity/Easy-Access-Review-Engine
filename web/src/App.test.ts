import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { assistantSuggestions, safeAssistantActionRoute } from "./chatbot/AssistantDrawer";
import { isAssistantAvailable } from "./App";

import { ActionMenu, ApplicationPicker, ExternalApiDocumentation, FunctionalRightsSummary, GUIDE_FOCUS, guidePendingCount, applicationSummary, accessDrawerBusinessContextOrder, accessDrawerTechnicalIdentifier, accessDrawerTitle, functionalRightsText, goldenAccessEditIsDirty, goldenAccessEditPayload, GuideChecklist, guideChecklistLabelKey, guideTranslation, joinPermissions, McpTokenOnce, mcpAccessStatus, reportBarPercent, reviewDerivedAccessText, reviewPermissionText, reviewTargetText, sourceSupportsAttributeMapping, splitPermissions, todayDateInputValue } from "./App";

describe("ActionMenu", () => {
  it("keeps secondary row actions in one labelled accessible menu", () => {
    const html = renderToStaticMarkup(
      createElement(ActionMenu, {
        label: "More actions for Alice",
        actions: [
          { label: "Reset password", onClick: () => undefined },
          { label: "Disable", danger: true, onClick: () => undefined },
        ],
      }),
    );

    expect(html).toContain('aria-label="More actions for Alice"');
    expect(html).toContain("Reset password");
    expect(html).toContain("Disable");
  });
});

describe("EARE Assistant launcher contracts", () => {
  it("fails closed when chatbot status is absent or unavailable", () => {
    expect(isAssistantAvailable(undefined)).toBe(false);
    expect(isAssistantAvailable({ available: false })).toBe(false);
    expect(isAssistantAvailable({ available: true })).toBe(true);
  });
  it("keeps suggestions contextual to the current page", () => {
    expect(assistantSuggestions("/campaigns/c-1")).toContain("Que reste-t-il à faire ?");
    expect(assistantSuggestions("/golden")).toContain("Qu'est-ce que je dois compléter ?");
    expect(assistantSuggestions("/reviews")).toContain("Que dois-je traiter ?");
  });

  it("accepts only internal action routes", () => {
    expect(safeAssistantActionRoute("/campaigns/c-1")).toBe("/campaigns/c-1");
    expect(safeAssistantActionRoute("javascript:alert(1)")).toBeNull();
    expect(safeAssistantActionRoute("https://example.test")).toBeNull();
    expect(safeAssistantActionRoute("data:text/html,x")).toBeNull();
    expect(safeAssistantActionRoute("//example.test/path")).toBeNull();
    expect(safeAssistantActionRoute("/campaigns\\\\secret")).toBeNull();
  });
});

describe("Campaign date defaults", () => {
  it("formats the local date for date inputs", () => {
    expect(todayDateInputValue(new Date(2026, 8, 29))).toBe("2026-09-29");
  });
});

describe("Campaign review labels", () => {
  it("explains ERP resources and actions without inventing CRM permissions", () => {
    expect(functionalRightsText({
      application: "ERP", access_display_name: "ERP-Accountant", functional_completeness: "complete",
      functional_rights: [
        { resource: "Invoices", capability: "read", capability_label: "Read" },
        { resource: "Invoices", capability: "approve", capability_label: "Approve" },
        { resource: "Suppliers", capability: "read", capability_label: "Read" },
      ],
    })).toBe("Invoices · Read, Approve\nSuppliers · Read");
    expect(functionalRightsText({
      functional_rights: [
        { application: "CRM", resource: "Customers", capability: "read", capability_label: "Read" },
        { application: "CRM", resource: "Customers", capability: "write", capability_label: "Write" },
        { application: "ERP", resource: "Invoices", capability: "read", capability_label: "Read" },
      ],
    })).toBe("CRM\n  Customers · Read, Write\nERP\n  Invoices · Read");
    expect(functionalRightsText({ application: "CRM", access_display_name: "CRM-Sales", functional_rights: [] }))
      .toBe("Functional permissions not exposed by the source.");
    expect(functionalRightsText({
      functional_rights: [],
      functional_completeness: "not_defined",
      functional_explanation: "Authorization rights depend on dynamic or conditional policies.",
    })).toContain("dynamic or conditional policies");
    expect(functionalRightsText({
      functional_completeness: "partial",
      functional_rights: [{ resource: "object-441", capability: "keycloak_scope_abc", capability_label: "perform_operation_xyz" }],
    })).toContain("perform_operation_xyz");
  });
  it("explains Keycloak role and group targets without hiding technical identifiers", () => {
    const role = reviewTargetText({
      access_provider: "keycloak-integration",
      access_display_name: "default-roles-eare-crashtest",
      permission: { identifier: "role" },
      target: { service: { identifier: "Keycloak", realm: "eare-crashtest" }, component: { identifier: "realm" }, resource: { identifier: "role-id" } },
    });
    expect(reviewPermissionText({ identifier: "role" })).toBe("Role assignment");
    expect(role.label).toBe("eare-crashtest · Role default-roles-eare-crashtest");
    expect(role.technical).toContain("role-id");
    expect(reviewPermissionText({ identifier: "member" })).toBe("Group membership");
    expect(reviewDerivedAccessText({ derived_accesses: [{ display_name: "view-profile" }, { display_name: "offline_access" }] })).toBe("view-profile, offline_access");
  });

  it("renders the undocumented CRM entry with an accessible Golden CTA", () => {
    const html = renderToStaticMarkup(createElement(FunctionalRightsSummary, {
      row: { application: "CRM", functional_rights: [] },
      onAction: () => undefined,
    }));
    expect(html).toContain("Not documented");
    expect(html).toContain("Source does not expose functional permissions.");
    expect(html).toContain("Define functional rights");
    expect(html).toContain("type=\"button\"");
  });
});

describe("External User API controls", () => {
  it("keeps documentation links hidden while the global API is disabled", () => {
    const html = renderToStaticMarkup(createElement(ExternalApiDocumentation, { enabled: false }));
    expect(html).toContain("External User API: Disabled");
    expect(html).toContain("Swagger and the external API are unavailable until the External User API is enabled.");
    expect(html).not.toContain('href="/swagger"');
  });

  it("shows same-origin Swagger and OpenAPI links only when enabled", () => {
    const html = renderToStaticMarkup(createElement(ExternalApiDocumentation, { enabled: true }));
    expect(html).toContain("External User API: Enabled");
    expect(html).toContain('href="/swagger"');
    expect(html).toContain('href="/openapi.json"');
    expect(html).toContain("noopener noreferrer");
  });
});

describe("MCP self-service controls", () => {
  it("distinguishes global and per-user disablement", () => {
    expect(mcpAccessStatus(false, true)).toBe("MCP server is currently disabled.");
    expect(mcpAccessStatus(true, false)).toBe("MCP access is disabled by an administrator.");
  });
  it("removes the one-time plaintext from closed-menu output", () => {
    expect(renderToStaticMarkup(createElement(McpTokenOnce, { menuOpen: true, token: "eare_mcp_test" }))).toContain("eare_mcp_test");
    expect(renderToStaticMarkup(createElement(McpTokenOnce, { menuOpen: false, token: "eare_mcp_test" }))).not.toContain("eare_mcp_test");
  });
});

describe("Report statistics", () => {
  it("calculates bounded percentages without dividing by zero", () => {
    expect(reportBarPercent(3, 10)).toBe(30);
    expect(reportBarPercent(15, 10)).toBe(100);
    expect(reportBarPercent(3, 0)).toBe(0);
    expect(reportBarPercent(-1, 10)).toBe(0);
  });
});


describe("source connector capabilities", () => {
  it("shows business mapping only when the connector capability allows it", () => {
    expect(sourceSupportsAttributeMapping({ attribute_mapping: true }, "active_directory")).toBe(true);
    expect(sourceSupportsAttributeMapping({ attribute_mapping: true }, "openldap")).toBe(true);
    expect(sourceSupportsAttributeMapping({ attribute_mapping: false }, "future_iam")).toBe(false);
  });

  it("derives mapping support for unsaved supported connector types", () => {
    expect(sourceSupportsAttributeMapping(undefined, "active_directory")).toBe(true);
    expect(sourceSupportsAttributeMapping(undefined, "openldap")).toBe(true);
    expect(sourceSupportsAttributeMapping(undefined, "future_iam")).toBe(false);
  });
});

describe("Golden access inline edit draft", () => {
  const original = {
    access_id: "access-1",
    access_provider: "crashtest-ldap",
    access_name: "crm-admin:member",
    application: "",
    business_permission: "",
    owner: "",
    original_application: "",
    original_business_permission: "",
    original_owner: "",
  };

  it("does not become dirty when edit mode starts", () => {
    expect(goldenAccessEditIsDirty(original)).toBe(false);
  });

  it("detects local changes without treating source fields as editable", () => {
    expect(goldenAccessEditIsDirty({ ...original, application: "CRM" })).toBe(true);
    expect(goldenAccessEditIsDirty({ ...original, access_name: "changed-source-value" })).toBe(false);
  });

  it("builds the enrichment payload from current local values", () => {
    expect(goldenAccessEditPayload({
      ...original,
      application: "CRM",
      business_permission: "admin",
      owner: "crashtest-ldap/alice",
    })).toEqual({
      access_id: "access-1",
      access_provider: "crashtest-ldap",
      access_name: "crm-admin:member",
      application: "CRM",
      business_permission: "admin",
      owner: "crashtest-ldap/alice",
    });
  });

  it("keeps deliberate clearing in the payload", () => {
    expect(goldenAccessEditPayload({ ...original, application: "", original_application: "CRM" }).application).toBe("");
  });
});

describe("Guide and Access density contracts", () => {
  it("uses translated short checklist labels and never exposes a missing recommendation key", () => {
    expect(guideChecklistLabelKey({ id: "operatorCoverage" })).toBe("guide.setupShort.operatorCoverage");
    expect(guideChecklistLabelKey({ id: "operator_coverage" })).toBe("guide.setupShort.operatorCoverage");
    expect(guideTranslation("guide.rec.operatorCoverage.title")).not.toContain("guide.rec.operatorCoverage.title");
  });

  it("renders checklist statuses and short labels without inline descriptions", () => {
    const html = renderToStaticMarkup(createElement(GuideChecklist, {
      items: [{ id: "operator_coverage", status: "attention", description: "Long operational explanation" }],
      text: (key: unknown) => String(key),
    }));
    expect(html).toContain("guide.setupShort.operatorCoverage");
    expect(html).toContain("!");
    expect(html).not.toContain("Long operational explanation");
  });

  it("keeps the human access name primary and technical identifier secondary", () => {
    const access = { display_name: "CRM Admin", name: "crm-admin:member" };
    expect(accessDrawerTitle(access)).toBe("CRM Admin");
    expect(accessDrawerTechnicalIdentifier(access)).toBe("crm-admin:member");
    expect(accessDrawerBusinessContextOrder).toEqual(["application", "business_permission", "owner", "description"]);
  });
});

describe("business permissions", () => {
  it("reads a combined permission as distinct rights and writes it back as one list", () => {
    expect(splitPermissions("read, write;execute | read")).toEqual(["read", "write", "execute"]);
    expect(splitPermissions("")).toEqual([]);
    expect(joinPermissions(["read", "write", "execute"])).toBe("read, write, execute");
  });
});

describe("applications", () => {
  it("shows each chosen application as a removable chip", () => {
    const html = renderToStaticMarkup(createElement(ApplicationPicker, { value: "CRM, ERP", options: ["CRM", "ERP", "Payroll"], onChange: () => undefined }));
    expect(html).toContain('aria-label="Remove CRM"');
    expect(html).toContain('aria-label="Remove ERP"');
    expect(html).toContain('role="combobox"');
  });

  it("keeps a long list of applications to one line when read", () => {
    expect(applicationSummary("CRM")).toBe("CRM");
    expect(applicationSummary("CRM, ERP, Payroll, HR")).toBe("CRM, ERP +2");
  });
});

describe("guide hand-holding", () => {
  const checklist = [
    { id: "sources", status: "complete" },
    { id: "read_only_accounts", status: "attention" },
    { id: "users", status: "not_started" },
  ];

  it("counts open setup steps for admins and actionable advice for others", () => {
    expect(guidePendingCount({ state: { setup_checklist: checklist } }, "ADMIN")).toBe(2);
    expect(guidePendingCount({ recommendations: [
      { status: "actionable", priority: "primary" },
      { status: "actionable", priority: "secondary" },
      { status: "completed", priority: "informational" },
    ] }, "OPERATOR")).toBe(1);
    expect(guidePendingCount(undefined, "ADMIN")).toBe(0);
  });

  it("shows how far the setup has come", () => {
    const html = renderToStaticMarkup(createElement(GuideChecklist, { items: checklist, text: (key: unknown) => String(key) }));
    expect(html).toContain('role="progressbar"');
    expect(html).toContain('aria-valuenow="1"');
    expect(html).toContain('aria-valuemax="3"');
  });

  it("walks the read-only step from the source card to the setting itself", () => {
    expect(GUIDE_FOCUS.read_only_accounts).toEqual(["configure-source", "read-only-account"]);
    expect(GUIDE_FOCUS.dedicated_read_only_accounts).toEqual(GUIDE_FOCUS.read_only_accounts);
  });
});
