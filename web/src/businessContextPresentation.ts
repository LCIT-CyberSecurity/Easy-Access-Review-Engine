export const BUSINESS_CONTEXT_FIELDS = [
  ["application", "Application"],
  ["business_permission", "Permission / business right"],
  ["resource", "Resource"],
  ["description", "Description"],
  ["owner", "Owner"],
  ["functional_rights", "Functional rights"],
  ["other", "Other"],
] as const;

export function conflictFields(context: unknown): string[] {
  if (!context || typeof context !== "object") return [];
  const fields = (context as { fields?: unknown }).fields;
  if (!fields || typeof fields !== "object") return [];
  return BUSINESS_CONTEXT_FIELDS.filter(([key]) => Boolean((fields as Record<string, { conflict?: boolean }>)[key]?.conflict))
    .map(([, label]) => label);
}

export function provenanceLabel(entry: { provenance?: unknown; mapping_mode?: unknown }): string {
  if (entry.provenance === "static") return "Value configured by IT";
  if (entry.provenance === "native_semantic") return "Information provided natively by the source";
  if (entry.mapping_mode === "configured") return "Directory value · mapping configured by IT";
  if (entry.mapping_mode === "default") return "Directory value · connector default";
  return "Value provided by the source";
}
