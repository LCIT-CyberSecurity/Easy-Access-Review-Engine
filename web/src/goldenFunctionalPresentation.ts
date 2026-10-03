export type FunctionalRightLike = Record<string, unknown>;
export type GoldenFunctionalRow = Record<string, unknown>;

export type FunctionalRightsGroup = {
  resource: string;
  capabilities: string[];
};

export type GoldenFunctionalPresentation = {
  status: "Complete" | "Partial" | "Not documented" | "Source suggestion available" | "Not statically resolved" | "System access";
  description: string;
  action: "Edit rights" | "Complete functional rights" | "Define functional rights" | "Review source suggestion" | "Review / define expected rights" | "Define rights";
  groups: FunctionalRightsGroup[];
  inheritedGroups: FunctionalRightsGroup[];
  origin: string;
};

const CAPABILITY_ORDER = ["read", "write", "approve", "execute", "delete", "grant", "admin"];
const STANDARD_CAPABILITY_LABELS: Record<string, { shortLabel: string; fullLabel: string }> = {
  read: { shortLabel: "R", fullLabel: "Read" },
  write: { shortLabel: "W", fullLabel: "Write" },
  delete: { shortLabel: "D", fullLabel: "Delete" },
  execute: { shortLabel: "X", fullLabel: "Execute" },
  approve: { shortLabel: "A", fullLabel: "Approve" },
  grant: { shortLabel: "G", fullLabel: "Grant" },
  admin: { shortLabel: "ADM", fullLabel: "Admin" },
};
const text = (value: unknown): string => typeof value === "string" ? value.trim() : value == null ? "" : String(value);

export type CapabilityPresentation = { shortLabel: string; fullLabel: string };

export function capabilityPresentation(capability: string): CapabilityPresentation {
  const fullLabel = text(capability) || "Unknown capability";
  const standard = STANDARD_CAPABILITY_LABELS[fullLabel.toLocaleLowerCase()];
  if (standard) return standard;
  const characters = [...fullLabel];
  return {
    shortLabel: characters.length > 5 ? `${characters.slice(0, 4).join("").toLocaleUpperCase()}…` : fullLabel.toLocaleUpperCase(),
    fullLabel,
  };
}

const ORIGIN_SHORT_LABELS: Record<string, string> = {
  "Manually defined in Golden": "Manual",
  "Validated in Golden": "Validated",
  "Golden extends source": "Extended",
  "Functional authorization changed": "Changed",
  "Observed from source": "Observed",
};

export function originShortLabel(origin: string): string {
  return ORIGIN_SHORT_LABELS[origin] ?? origin;
}

const rightResource = (right: FunctionalRightLike): string => {
  const resource: unknown = right.resource ?? (right.target as FunctionalRightLike | undefined)?.resource;
  if (typeof resource === "string") return resource.trim() || "Resource not named";
  const node = resource && typeof resource === "object" ? resource as FunctionalRightLike : undefined;
  return text(node?.display_name ?? node?.identifier) || "Resource not named";
};

const rightCapability = (right: FunctionalRightLike): string =>
  text(right.capability_label ?? right.capability ?? right.capability_id) || "Unknown capability";

const rightKey = (right: FunctionalRightLike): string => `${rightResource(right).toLocaleLowerCase()}\u0000${rightCapability(right).toLocaleLowerCase()}`;

export function functionalRightsGroups(rights: unknown): FunctionalRightsGroup[] {
  const grouped = new Map<string, Set<string>>();
  if (!Array.isArray(rights)) return [];
  for (const value of rights) {
    if (!value || typeof value !== "object") continue;
    const right = value as FunctionalRightLike;
    const resource = rightResource(right);
    const capabilities = grouped.get(resource) ?? new Set<string>();
    capabilities.add(rightCapability(right));
    grouped.set(resource, capabilities);
  }
  const rank = (capability: string): [number, string] => {
    const index = CAPABILITY_ORDER.indexOf(capability.toLocaleLowerCase());
    return [index < 0 ? CAPABILITY_ORDER.length : index, capability.toLocaleLowerCase()];
  };
  return [...grouped.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([resource, capabilities]) => ({
      resource,
      capabilities: [...capabilities].sort((left, right) => {
        const [leftRank, leftName] = rank(left);
        const [rightRank, rightName] = rank(right);
        return leftRank - rightRank || leftName.localeCompare(rightName);
      }),
    }));
}

const sameRights = (left: unknown, right: unknown): boolean => {
  const leftKeys = Array.isArray(left) ? left.filter((item): item is FunctionalRightLike => !!item && typeof item === "object").map(rightKey).sort() : [];
  const rightKeys = Array.isArray(right) ? right.filter((item): item is FunctionalRightLike => !!item && typeof item === "object").map(rightKey).sort() : [];
  return leftKeys.length === rightKeys.length && leftKeys.every((value, index) => value === rightKeys[index]);
};

const containsAll = (superset: unknown, subset: unknown): boolean => {
  const values = new Set(Array.isArray(superset) ? superset.filter((item): item is FunctionalRightLike => !!item && typeof item === "object").map(rightKey) : []);
  const required = Array.isArray(subset) ? subset.filter((item): item is FunctionalRightLike => !!item && typeof item === "object").map(rightKey) : [];
  return required.every((value) => values.has(value));
};

const additionalRights = (effective: unknown, direct: unknown): FunctionalRightLike[] => {
  const directKeys = new Set(Array.isArray(direct) ? direct.filter((item): item is FunctionalRightLike => !!item && typeof item === "object").map(rightKey) : []);
  return Array.isArray(effective)
    ? effective.filter((item): item is FunctionalRightLike => !!item && typeof item === "object" && !directKeys.has(rightKey(item)))
    : [];
};

export function goldenFunctionalPresentation(row: GoldenFunctionalRow): GoldenFunctionalPresentation {
  const expected = Array.isArray(row.direct_functional_rights) ? row.direct_functional_rights : row.functional_rights;
  const observed = row.observed_functional_rights;
  const completeness = text(row.completeness || row.functional_completeness);
  const hasExpected = completeness === "complete" || completeness === "partial" || (Array.isArray(expected) && expected.length > 0);
  const observedRights = Array.isArray(observed) ? observed : [];
  const systemAccess = Boolean(row.system_access);
  const explanation = text(row.functional_explanation || row.source_functional_explanation);
  const unresolved = text(row.observed_completeness) === "not_defined" && explanation.toLocaleLowerCase().includes("authorization configuration exists");

  if (hasExpected) {
    const origin = observedRights.length === 0
      ? "Manually defined in Golden"
      : sameRights(expected, observedRights)
        ? "Validated in Golden"
        : containsAll(expected, observedRights)
          ? "Golden extends source"
          : "Functional authorization changed";
    return {
      status: completeness === "partial" ? "Partial" : "Complete",
      description: completeness === "partial" ? "Some expected functional rights are not fully defined." : "",
      action: completeness === "partial" ? "Complete functional rights" : "Edit rights",
      groups: functionalRightsGroups(expected),
      inheritedGroups: functionalRightsGroups(additionalRights(row.effective_functional_rights, expected)),
      origin,
    };
  }
  if (systemAccess) return { status: "System access", description: "No business functional model defined.", action: "Define rights", groups: [], inheritedGroups: [], origin: "" };
  if (unresolved) return { status: "Not statically resolved", description: "Authorization configuration exists, but some resulting rights cannot be determined statically.", action: "Review / define expected rights", groups: functionalRightsGroups(observedRights), inheritedGroups: [], origin: "" };
  if (observedRights.length) return { status: "Source suggestion available", description: "Observed from source.", action: "Review source suggestion", groups: functionalRightsGroups(observedRights), inheritedGroups: [], origin: "Observed from source" };
  return {
    status: "Not documented",
    description: text(row.application) ? "Source does not expose functional permissions." : "No application or functional model has been defined.",
    action: "Define functional rights",
    groups: [],
    inheritedGroups: [],
    origin: "",
  };
}
