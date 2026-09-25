export function currentStateLabels(observed: boolean, expected: boolean): string[] {
  return ["Observed " + (observed ? "✓" : "Not observed"), "Expected " + (expected ? "✓" : "Not expected")];
}

export function pageCount(total: number, limit: number): number {
  return Math.max(1, Math.ceil(total / Math.max(1, limit)));
}
export function pageLabel(total: number, limit: number, offset: number): string {
  if (!total) return "Showing 0–0 of 0";
  return `Showing ${offset + 1}–${Math.min(offset + limit, total)} of ${total}`;
}
export function roleHome(role: string): string {
  if (role === "GROUP_OWNER") return "/reviews";
  if (role === "BUSINESS_ADMIN") return "/actions";
  if (role === "REMEDIATION_MANAGER") return "/actions";
  return "/";
}
export const roleNavigationContract = {
  ADMIN: { home: "/", visible: ["reports", "actions", "system"] },
  OPERATOR: { home: "/", visible: ["campaigns", "reports", "actions"], hidden: ["users", "authentication", "audit"] },
  GROUP_OWNER: { home: "/reviews", visible: ["myReviews"], hidden: ["campaigns", "reports", "sources"] },
  BUSINESS_ADMIN: { home: "/actions", visible: ["actions"], remediationReadOnly: true },
  REMEDIATION_MANAGER: { home: "/actions", visible: ["actions"], remediationUpdate: true },
} as const;
export function pendingFirst(a: { decision?: unknown }, b: { decision?: unknown }): number {
  return Number(Boolean(a.decision)) - Number(Boolean(b.decision));
}
export function validProviderScope(scopeType: string, providers: string[]): boolean {
  return scopeType !== "providers" || providers.some((provider) => provider.trim().length > 0);
}
export function campaignCtas(status: string, pending: number): string[] {
  if (status === "draft") return ["open", "cancel"];
  if (status === "open") return pending ? ["close-disabled"] : ["close"];
  if (status === "closed") return ["promote", "report"];
  return [];
}
export function campaignActionTarget(action: string, campaignId: string): string | null {
  return action === "report" ? `/reports?campaign=${encodeURIComponent(campaignId)}` : null;
}
