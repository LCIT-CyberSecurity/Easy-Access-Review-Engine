import { describe, expect, it } from "vitest";
import {
  campaignActionTarget,
  campaignCtas,
  currentStateLabels,
  pageCount,
  pageLabel,
  pendingFirst,
  roleHome,
  validProviderScope,
} from "./projections";

describe("currentStateLabels", () => {
  it("renders observed and expected independently", () => {
    expect(currentStateLabels(true, true)).toEqual(["Observed ✓", "Expected ✓"]);
    expect(currentStateLabels(true, false)).toEqual(["Observed ✓", "Expected Not expected"]);
  });
});
describe("pagination", () => {
  it("calculates stable pages and visible ranges", () => {
    expect(pageCount(428, 25)).toBe(18);
    expect(pageLabel(428, 25, 25)).toBe("Showing 26–50 of 428");
    expect(pageLabel(0, 25, 0)).toBe("Showing 0–0 of 0");
  });
});
describe("campaignCtas", () => {
  it("keeps close disabled while decisions are pending", () => {
    expect(campaignCtas("draft", 2)).toEqual(["open", "cancel"]);
    expect(campaignCtas("open", 2)).toEqual(["close-disabled"]);
    expect(campaignCtas("open", 0)).toEqual(["close"]);
    expect(campaignCtas("closed", 0)).toEqual(["promote", "report"]);
  });
  it("navigates report actions to the existing reports workflow", () => {
    expect(campaignActionTarget("report", "campaign 1")).toBe("/reports?campaign=campaign%201");
    expect(campaignActionTarget("close", "campaign-1")).toBeNull();
  });
});
describe("role landing", () => {
  it("keeps restricted roles away from the dashboard", () => {
    expect(roleHome("ADMIN")).toBe("/");
    expect(roleHome("OPERATOR")).toBe("/");
    expect(roleHome("GROUP_OWNER")).toBe("/reviews");
    expect(roleHome("BUSINESS_ADMIN")).toBe("/actions");
  });
});
describe("review ordering", () => {
  it("puts reviews without a decision first", () => {
    const rows = [{ id: "approved", decision: "approve" }, { id: "pending" }];
    expect(rows.sort(pendingFirst).map((row) => row.id)).toEqual(["pending", "approved"]);
  });
});
describe("provider campaign scope", () => {
  it("requires a real provider selection", () => {
    expect(validProviderScope("all", [])).toBe(true);
    expect(validProviderScope("providers", [])).toBe(false);
    expect(validProviderScope("providers", ["corp-ad"])).toBe(true);
  });
});
