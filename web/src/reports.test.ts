import { describe, expect, it } from "vitest";
import { Reports } from "./App";

describe("native Reports workspace regression", () => {
  it("does not embed a standalone report document", () => {
    const source = String(Reports);
    expect(source).not.toMatch(/iframe|<object|<embed|dangerouslySetInnerHTML|inline=true/i);
    expect(source).toContain("Download HTML");
    expect(source).toContain("Download PDF");
    expect(source).toContain("View all actions");
    expect(source).toContain("Executive summary");
    expect(source).toContain("Detailed results");
  });
});
