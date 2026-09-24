import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ActionMenu, goldenAccessEditIsDirty, goldenAccessEditPayload, sourceSupportsAttributeMapping } from "./App";

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
