export type GoldenFunctionalRight = {
  capability_id?: unknown;
  target?: {
    service?: { identifier?: unknown } | null;
    component?: { identifier?: unknown } | null;
    resource?: { identifier?: unknown } | null;
  } | null;
};

const nonEmpty = (value: unknown): boolean => typeof value === "string" && value.trim().length > 0;

export function goldenFunctionalRightsAreValid(rights: unknown, _completeness: unknown): boolean {
  if (!Array.isArray(rights)) return false;
  return rights.every((right): right is GoldenFunctionalRight => {
    if (!right || typeof right !== "object" || !nonEmpty((right as GoldenFunctionalRight).capability_id)) return false;
    const target = (right as GoldenFunctionalRight).target;
    if (!target || typeof target !== "object") return false;
    return [target.service, target.component, target.resource].some(
      (node) => Boolean(node && typeof node === "object" && nonEmpty(node.identifier)),
    );
  });
}
