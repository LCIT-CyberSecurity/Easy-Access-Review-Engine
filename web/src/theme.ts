// The interface ships two styles. "default" is the product's own blue chrome; "violet"
// carries the sign-in vocabulary — violet accent, display typography, stated colour — into
// the application. The choice is per browser: it changes nothing the server knows about.
export type ThemeId = "default" | "azure" | "violet" | "studio";

export const THEMES: { id: ThemeId; name: string; summary: string; detail: string }[] = [
  {
    id: "default",
    name: "Blue",
    summary: "Neutral operating chrome",
    detail: "Light rail, blue accent and compact tables. Built for long review sessions where the data carries the page.",
  },
  {
    id: "azure",
    name: "Azure",
    summary: "The sign-in blue, kept light",
    detail: "The blue of the sign-in panel used as a tint rather than a field: pale blue canvas, white surfaces, no dark chrome.",
  },
  {
    id: "violet",
    name: "Violet",
    summary: "The sign-in screen, everywhere",
    detail: "Violet accent and display typography taken from the LCIT sign-in screen.",
  },
  {
    id: "studio",
    name: "Studio",
    summary: "Precise, near monochrome, one accent",
    detail: "Hairline rules instead of shadows, a tightened type scale with Inter's alternate glyphs, a denser grid and a single indigo accent. Built like the tools engineers keep open all day.",
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
