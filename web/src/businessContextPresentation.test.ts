import { describe, expect, it } from "vitest";
import { conflictFields, provenanceLabel } from "./businessContextPresentation";

describe("business context presentation", () => {
  it("shows no warning without conflicts and names every conflicting field", () => {
    expect(conflictFields({ fields: { application: { conflict: false } } })).toEqual([]);
    expect(conflictFields({ fields: { application: { conflict: true }, owner: { conflict: true } } })).toEqual(["Application", "Owner"]);
  });
  it("uses a business label while retaining technical metadata separately", () => {
    const entry = { provenance: "source_attribute", mapping_mode: "configured", attribute: "extensionAttribute6" };
    expect(provenanceLabel(entry)).toBe("Directory value · mapping configured by IT");
    expect(provenanceLabel(entry)).not.toContain(entry.attribute);
    expect(provenanceLabel({ provenance: "source_attribute", mapping_mode: "default" })).toContain("connector default");
    expect(provenanceLabel({ provenance: "static" })).toContain("configured by IT");
    expect(provenanceLabel({ provenance: "native_semantic" })).toContain("natively");
  });
});
