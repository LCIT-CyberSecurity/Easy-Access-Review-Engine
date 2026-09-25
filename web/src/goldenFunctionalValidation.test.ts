import { describe, expect, it } from "vitest";
import { goldenFunctionalRightsAreValid } from "./goldenFunctionalValidation";

describe("Golden V2 functional right validation", () => {
  it("validates every multi-right row from the API payload", () => {
    const rights = [
      { capability_id: "read", target: { resource: { identifier: "invoices" } }, native_permission: "SELECT" },
      { capability_id: "write", target: { component: { identifier: "billing" } } },
    ];
    expect(goldenFunctionalRightsAreValid(rights, "partial")).toBe(true);
    expect(goldenFunctionalRightsAreValid([{ ...rights[0], capability_id: "" }, rights[1]], "partial")).toBe(false);
    expect(goldenFunctionalRightsAreValid([{ capability_id: "read", target: { resource: {} } }], "partial")).toBe(false);
  });

  it("allows an empty not-defined model, as accepted by the backend", () => {
    expect(goldenFunctionalRightsAreValid([], "not_defined")).toBe(true);
  });
});
