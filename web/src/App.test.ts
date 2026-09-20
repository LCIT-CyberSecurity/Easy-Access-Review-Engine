import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ActionMenu, sourceSupportsAttributeMapping } from "./App";

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
