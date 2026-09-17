import { describe, expect, it } from "vitest";
import { campaignCtas, currentStateLabels, pageCount, pageLabel } from "./projections";

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
});
