import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ActionMenu, ApplicationPicker, GUIDE_FOCUS, guidePendingCount, applicationSummary, accessDrawerBusinessContextOrder, accessDrawerTechnicalIdentifier, accessDrawerTitle, goldenAccessEditIsDirty, goldenAccessEditPayload, GuideChecklist, guideChecklistLabelKey, guideTranslation, joinPermissions, sourceSupportsAttributeMapping, splitPermissions } from "./App";

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
