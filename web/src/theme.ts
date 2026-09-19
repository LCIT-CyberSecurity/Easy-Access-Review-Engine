// The interface ships two styles. "default" is the product's own neutral chrome; "lcit"
// carries the sign-in vocabulary — midnight rail, violet accent, display typography — into
// the application. The choice is per browser: it changes nothing the server knows about.
export type ThemeId = "default" | "lcit";

export const THEMES: { id: ThemeId; name: string; summary: string; detail: string }[] = [
  {
    id: "default",
    name: "Default",
    summary: "Neutral operating chrome",
    detail: "Light rail, blue accent and compact tables. Built for long review sessions where the data carries the page.",
  },
  {
    id: "lcit",
    name: "LCIT style",
    summary: "The sign-in screen, everywhere",
    detail: "Midnight rail, violet accent and display typography taken from the LCIT sign-in screen.",
  },
];

const STORAGE_KEY = "eare.theme";
const DEFAULT_THEME: ThemeId = "default";

function isTheme(value: unknown): value is ThemeId {
  return THEMES.some((theme) => theme.id === value);
}

export function readTheme(): ThemeId {
  // Storage is unavailable in private windows and can throw rather than return null.
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    return isTheme(stored) ? stored : DEFAULT_THEME;
  } catch {
    return DEFAULT_THEME;
  }
}

export function applyTheme(theme: ThemeId): void {
  const root = document.documentElement;
  if (theme === DEFAULT_THEME) root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", theme);
}

export function storeTheme(theme: ThemeId): void {
  try {
    if (theme === DEFAULT_THEME) window.localStorage.removeItem(STORAGE_KEY);
    else window.localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // A browser that refuses storage still gets the theme for this session.
  }
}
