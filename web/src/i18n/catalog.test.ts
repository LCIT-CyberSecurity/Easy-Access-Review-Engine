// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import en from "./en.json";
import fr from "./fr.json";
import es from "./es.json";
import pt from "./pt.json";
import itLocale from "./it.json";
import ar from "./ar.json";
import { isLocale, setLocale, SUPPORTED_LOCALES } from "./index";

const keys = (value: unknown, prefix = ""): string[] =>
  typeof value === "object" && value !== null
    ? Object.entries(value).flatMap(([key, child]) => keys(child, prefix ? `${prefix}.${key}` : key))
    : [prefix];

describe("WebUI locale contract", () => {
  it("supports English, French, Spanish, Portuguese, Italian and Arabic", () => {
    expect(SUPPORTED_LOCALES).toEqual(["en", "fr", "es", "pt", "it", "ar"]);
    expect(isLocale("invalid")).toBe(false);
    expect(isLocale("fr")).toBe(true);
  });

  it("keeps every catalogue aligned with the English source", () => {
    const source = keys(en).sort();
    for (const catalogue of [fr, es, pt, itLocale, ar]) expect(keys(catalogue).sort()).toEqual(source);
  });

  it("translates the core EARE Guide labels in every supported locale", () => {
    const core = ["open", "currentSituation", "next", "onboardingTitle"];
    for (const catalogue of [fr, es, pt, ar, itLocale]) {
      for (const key of core) expect(catalogue.guide[key as keyof typeof catalogue.guide]).not.toBe(en.guide[key as keyof typeof en.guide]);
    }
  });

  it("translates representative workflow, authentication and role-help copy", () => {
    const representative = [
      "common.filter",
      "common.apply",
      "common.back",
      "auth.intro",
      "campaign.unresolvedReviewers.description",
      "golden.manualValueHint",
      "roles.help.businessAdmin",
      "roles.help.remediationManager",
    ];
    const read = (catalogue: typeof en, path: string) => path.split(".").reduce<unknown>((value, part) => (value as Record<string, unknown>)[part], catalogue);
    for (const catalogue of [fr, es, pt, ar, itLocale]) {
      for (const path of representative) expect(read(catalogue, path)).not.toBe(read(en, path));
    }
  });

  it("normalizes invalid locale input to English without touching data values", async () => {
    await setLocale("invalid");
    expect(document.documentElement.lang).toBe("en");
    expect(document.documentElement.dir).toBe("ltr");
    expect(window.localStorage.getItem("eare.ui.locale")).toBe("en");
    const technical = ["GG-CRM-Compta", "NexaByte CRM", "openldap-corp", "salesdb.public.orders", "SELECT", "member", "s3:GetObject", "user comment"];
    expect(technical).toEqual(["GG-CRM-Compta", "NexaByte CRM", "openldap-corp", "salesdb.public.orders", "SELECT", "member", "s3:GetObject", "user comment"]);
  });

  it("switches Arabic to RTL and back to LTR", async () => {
    await setLocale("ar");
    expect(window.localStorage.getItem("eare.ui.locale")).toBe("ar");
    expect(document.documentElement.lang).toBe("ar");
    expect(document.documentElement.dir).toBe("rtl");
    await setLocale("fr");
    expect(document.documentElement.lang).toBe("fr");
    expect(document.documentElement.dir).toBe("ltr");
  });
});
