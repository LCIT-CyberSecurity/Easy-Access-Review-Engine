// The interface has two independent settings, both stored per browser and both
// invisible to the server: an *appearance* (light, dark, or whatever the system
// asks for) and a *style* (which palette and type treatment the product wears).
// Keeping them apart means every style works in both appearances, instead of
// dark being a fifth style that has to be maintained on its own.

export type ThemeId = "default" | "aurora" | "azure" | "violet" | "studio";
export type Appearance = "light" | "dark" | "system";

export const THEMES: { id: ThemeId; name: string; summary: string; detail: string }[] = [
  {
    id: "default",
    name: "Blue",
    summary: "The product's own chrome",
    detail:
      "Cool neutrals, the product's blue accent and a calm grid. Built for long review sessions where the data carries the page rather than the decoration.",
  },
  {
    id: "aurora",
    name: "Aurora",
    summary: "Indigo, the redesign's first palette",
    detail: "Cool neutrals with an indigo-to-violet accent and a soft aurora wash behind the page.",
  },
  {
    id: "azure",
    name: "Azure",
    summary: "The sign-in blue, kept light",
    detail: "The blue of the sign-in panel used as a tint rather than a field: pale blue canvas, white surfaces.",
  },
  {
    id: "violet",
    name: "Violet",
    summary: "The LCIT sign-in palette",
    detail: "Violet accent and display typography taken from the LCIT sign-in screen, carried across every page.",
  },
  {
    id: "studio",
    name: "Studio",
    summary: "Precise, near monochrome",
    detail:
      "Hairline rules instead of shadows, a tightened type scale, a denser grid and a graphite accent. Built like the tools engineers keep open all day.",
  },
];

export const APPEARANCES: { id: Appearance; labelKey: string }[] = [
  { id: "light", labelKey: "settings.appearanceLight" },
  { id: "dark", labelKey: "settings.appearanceDark" },
  { id: "system", labelKey: "settings.appearanceSystem" },
];

const THEME_KEY = "eare.theme";
const APPEARANCE_KEY = "eare.appearance";
const DEFAULT_THEME: ThemeId = "default";
const DEFAULT_APPEARANCE: Appearance = "light";

function isTheme(value: unknown): value is ThemeId {
  return THEMES.some((theme) => theme.id === value);
}

function isAppearance(value: unknown): value is Appearance {
  return value === "light" || value === "dark" || value === "system";
}

/** Storage is unavailable in private windows and can throw rather than return null. */
function read(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function write(key: string, value: string | null): void {
  try {
    if (value === null) window.localStorage.removeItem(key);
    else window.localStorage.setItem(key, value);
  } catch {
    // A browser that refuses storage still gets the choice for this session.
  }
}

export function readTheme(): ThemeId {
  const stored = read(THEME_KEY);
  return isTheme(stored) ? stored : DEFAULT_THEME;
}

export function applyTheme(theme: ThemeId): void {
  const root = document.documentElement;
  if (theme === DEFAULT_THEME) root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", theme);
}

export function storeTheme(theme: ThemeId): void {
  write(THEME_KEY, theme === DEFAULT_THEME ? null : theme);
}

export function readAppearance(): Appearance {
  const stored = read(APPEARANCE_KEY);
  return isAppearance(stored) ? stored : DEFAULT_APPEARANCE;
}

function systemPrefersDark(): boolean {
  return typeof window.matchMedia === "function" && window.matchMedia("(prefers-color-scheme: dark)").matches;
}

/** The attribute carries the *resolved* appearance, so CSS never has to ask twice. */
export function applyAppearance(appearance: Appearance): void {
  const dark = appearance === "dark" || (appearance === "system" && systemPrefersDark());
  const root = document.documentElement;
  if (dark) root.setAttribute("data-appearance", "dark");
  else root.removeAttribute("data-appearance");
}

export function storeAppearance(appearance: Appearance): void {
  write(APPEARANCE_KEY, appearance === DEFAULT_APPEARANCE ? null : appearance);
}

/**
 * Keeps the resolved appearance in step with the operating system while the
 * viewer has chosen to follow it. Returns an unsubscribe function.
 */
export function watchSystemAppearance(current: () => Appearance): () => void {
  if (typeof window.matchMedia !== "function") return () => undefined;
  const query = window.matchMedia("(prefers-color-scheme: dark)");
  const react = () => {
    if (current() === "system") applyAppearance("system");
  };
  query.addEventListener("change", react);
  return () => query.removeEventListener("change", react);
}
