import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import en from "./en.json";
import fr from "./fr.json";
import es from "./es.json";
import pt from "./pt.json";
import it from "./it.json";
import ar from "./ar.json";

export const SUPPORTED_LOCALES = ["en", "fr", "es", "pt", "it", "ar"] as const;
export type Locale = (typeof SUPPORTED_LOCALES)[number];
export const LOCALE_LABELS: Record<Locale, string> = {
  en: "English",
  fr: "Français",
  es: "Español",
  pt: "Português",
  it: "Italiano",
  ar: "العربية",
};
const STORAGE_KEY = "eare.ui.locale";

export function isLocale(value: string | null | undefined): value is Locale {
  return Boolean(value && (SUPPORTED_LOCALES as readonly string[]).includes(value));
}

function readLocale(): Locale {
  try {
    const value = window.localStorage.getItem(STORAGE_KEY);
    return isLocale(value) ? value : "en";
  } catch {
    return "en";
  }
}

function applyDocumentLocale(locale: Locale) {
  if (typeof document === "undefined") return;
  document.documentElement.lang = locale;
  document.documentElement.dir = locale === "ar" ? "rtl" : "ltr";
}

export async function setLocale(value: string): Promise<Locale> {
  const locale: Locale = isLocale(value) ? value : "en";
  await i18n.changeLanguage(locale);
  applyDocumentLocale(locale);
  try {
    window.localStorage.setItem(STORAGE_KEY, locale);
  } catch {
    // Locale selection still applies for this session when storage is unavailable.
  }
  return locale;
}

void i18n.use(initReactI18next).init({
  resources: { en: { translation: en }, fr: { translation: fr }, es: { translation: es }, pt: { translation: pt }, it: { translation: it }, ar: { translation: ar } },
  lng: readLocale(),
  fallbackLng: "en",
  supportedLngs: SUPPORTED_LOCALES,
  interpolation: { escapeValue: false },
  returnNull: false,
});
applyDocumentLocale(isLocale(i18n.language) ? i18n.language : "en");

export { i18n };
export default i18n;
