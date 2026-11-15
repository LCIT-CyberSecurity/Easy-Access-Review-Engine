// @vitest-environment jsdom
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Login } from "./App";
import { getJson, login } from "./api/client";

vi.mock("./api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./api/client")>();
  return { ...actual, getJson: vi.fn(), login: vi.fn() };
});

const principal = { subject: "user-1", username: "user", display_name: "User", role: "ADMIN", scopes: [], must_change_password: false };
let root: Root;
let host: HTMLDivElement;
let queryClient: QueryClient;

function setOptions({ sso = false, directory = false, local = true }: { sso?: boolean; directory?: boolean; local?: boolean } = {}) {
  vi.mocked(getJson).mockImplementation(async (path) => path === "auth/oidc/config"
    ? { enabled: sso, name: "Secret Keycloak", button_label: "Continue with Keycloak" }
    : { directory_enabled: directory, local_available: local });
}

async function renderLogin() {
  host = document.createElement("div");
  document.body.append(host);
  queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  root = createRoot(host);
  await act(async () => {
    root.render(createElement(QueryClientProvider, { client: queryClient }, createElement(Login)));
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); });
}

afterEach(async () => {
  if (root) await act(async () => root.unmount());
  host?.remove();
  queryClient?.clear();
});

beforeEach(() => {
  vi.clearAllMocks();
  window.history.replaceState({}, "", "/login");
  window.sessionStorage.clear();
  vi.mocked(login).mockResolvedValue(principal);
});

describe("login presentation and method selection", () => {
  it("shows one generic SSO action when SSO is the only method", async () => {
    setOptions({ sso: true, local: false });
    await renderLogin();
    const button = host.querySelector<HTMLAnchorElement>('a[href="/api/auth/oidc/login"]');
    expect(button?.textContent).toBe("Sign in");
    expect(button?.textContent).not.toContain("Keycloak");
    expect(host.querySelector("details")).toBeNull();
    expect(host.querySelector('input[autocomplete="username"]')).toBeNull();
  });

  it("keeps local recovery collapsed below SSO until requested", async () => {
    setOptions({ sso: true, local: true });
    await renderLogin();
    const details = host.querySelector<HTMLDetailsElement>("details.auth-methods");
    expect(details?.open).toBe(false);
    const summary = details?.querySelector<HTMLElement>("summary");
    expect(summary?.textContent).toBe("Other sign-in methods");
    summary?.focus();
    expect(document.activeElement).toBe(summary);
    await act(async () => details?.querySelector("summary")?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true })));
    expect(details?.open).toBe(true);
    expect(details?.querySelector('input[autocomplete="username"]')).not.toBeNull();
  });

  it("offers an explicit directory/local choice with only one credential form", async () => {
    setOptions({ sso: true, directory: true, local: true });
    await renderLogin();
    const details = host.querySelector<HTMLDetailsElement>("details.auth-methods");
    await act(async () => details?.querySelector("summary")?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true })));
    expect(details?.querySelectorAll('input[type="radio"]')).toHaveLength(2);
    expect(details?.querySelectorAll('input[autocomplete="username"]')).toHaveLength(1);
    expect(details?.querySelector<HTMLInputElement>('input[value="directory"]')?.checked).toBe(true);
    await act(async () => details?.querySelector<HTMLInputElement>('input[value="local"]')?.click());
    expect(details?.querySelector<HTMLInputElement>('input[value="local"]')?.checked).toBe(true);
    expect(details?.querySelectorAll('input[autocomplete="username"]')).toHaveLength(1);
  });

  it("uses the directory form as primary without SSO and keeps local secondary", async () => {
    setOptions({ directory: true, local: true });
    await renderLogin();
    expect(host.querySelector('input[autocomplete="username"]')).not.toBeNull();
    expect(host.querySelector('a[href="/api/auth/oidc/login"]')).toBeNull();
    expect(host.querySelectorAll("details.auth-methods")).toHaveLength(1);
    expect(host.querySelector("details.auth-methods summary")?.textContent).toBe("Local account");
  });

  it("shows local credentials directly when local is the only method", async () => {
    setOptions({ local: true });
    await renderLogin();
    expect(host.querySelector('input[autocomplete="username"]')).not.toBeNull();
    expect(host.querySelector("details")).toBeNull();
  });

  it("preserves the signed-out confirmation and accessible password control", async () => {
    window.sessionStorage.setItem("aurora.signed-out", "1");
    setOptions({ local: true });
    await renderLogin();
    expect(host.querySelector('[role="status"]')?.textContent).toContain("You have been signed out");
    const password = host.querySelector<HTMLInputElement>('input[autocomplete="current-password"]');
    expect(password?.type).toBe("password");
    const showPassword = host.querySelector<HTMLButtonElement>('button[aria-label="Show password"]');
    expect(showPassword).not.toBeNull();
    await act(async () => showPassword?.click());
    expect(host.querySelector<HTMLInputElement>('input[autocomplete="current-password"]')?.type).toBe("text");
  });

  it("shows a clear administrator message when no method is available", async () => {
    setOptions({ local: false });
    await renderLogin();
    expect(host.querySelector('[role="alert"]')?.textContent).toContain("No sign-in method is available");
    expect(host.querySelector('input[autocomplete="username"]')).toBeNull();
  });

  it("retains local access and a readable error if the SSO endpoint is unavailable", async () => {
    vi.mocked(getJson).mockImplementation(async (path) => {
      if (path === "auth/oidc/config") throw new Error("offline");
      return { directory_enabled: false, local_available: true };
    });
    window.history.replaceState({}, "", "/login?auth_error=sso_unavailable");
    await renderLogin();
    expect(host.querySelector('input[autocomplete="username"]')).not.toBeNull();
    expect(host.querySelector('[role="alert"]')?.textContent).toContain("identity provider is unavailable");
  });

  it("keeps the OIDC error visible beside SSO and local recovery", async () => {
    setOptions({ sso: true, local: true });
    window.history.replaceState({}, "", "/login?auth_error=sso_unavailable");
    await renderLogin();
    expect(host.querySelector('a[href="/api/auth/oidc/login"]')).not.toBeNull();
    expect(host.querySelector('[role="alert"]')?.textContent).toContain("identity provider is unavailable");
    expect(host.querySelector("details.auth-methods summary")?.textContent).toBe("Other sign-in methods");
  });

  it("retains the local recovery option if the methods endpoint is unavailable", async () => {
    vi.mocked(getJson).mockImplementation(async (path) => {
      if (path === "auth/methods") throw new Error("offline");
      return { enabled: true, name: "Secret Keycloak" };
    });
    await renderLogin();
    expect(host.querySelector('a[href="/api/auth/oidc/login"]')).not.toBeNull();
    expect(host.querySelector("details.auth-methods summary")?.textContent).toBe("Other sign-in methods");
  });

  it("submits the selected directory method through the existing login API", async () => {
    setOptions({ directory: true, local: true });
    await renderLogin();
    const form = host.querySelector("form.auth-credentials");
    await act(async () => form?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
    expect(login).toHaveBeenCalledWith("", "", "directory");
  });

  it("submits the selected local method through the existing login API", async () => {
    setOptions({ sso: true, directory: true, local: true });
    await renderLogin();
    const details = host.querySelector<HTMLDetailsElement>("details.auth-methods");
    await act(async () => details?.querySelector("summary")?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true })));
    await act(async () => details?.querySelector<HTMLInputElement>('input[value="local"]')?.click());
    await act(async () => details?.querySelector("form")?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
    expect(login).toHaveBeenCalledWith("", "", "local");
  });

  it("shows a failed directory login while leaving the local fallback available", async () => {
    setOptions({ directory: true, local: true });
    vi.mocked(login).mockRejectedValue(new Error("Invalid username or password"));
    await renderLogin();
    await act(async () => host.querySelector("form.auth-credentials")?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
    expect(host.querySelector('[role="alert"]')?.textContent).toContain("Invalid username or password");
    expect(host.querySelector("details.auth-methods summary")?.textContent).toBe("Local account");
  });

  it("keeps local credentials visible after an authentication failure", async () => {
    setOptions({ local: true });
    vi.mocked(login).mockRejectedValue(new Error("Invalid username or password"));
    await renderLogin();
    await act(async () => host.querySelector("form.auth-credentials")?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
    expect(host.querySelector('[role="alert"]')?.textContent).toContain("Invalid username or password");
    expect(host.querySelector('input[autocomplete="username"]')).not.toBeNull();
  });

  it("translates the primary login action and alternative label in French", async () => {
    const { i18n } = await import("./i18n");
    await i18n.changeLanguage("fr");
    setOptions({ sso: true, local: true });
    await renderLogin();
    expect(host.querySelector('a[href="/api/auth/oidc/login"]')?.textContent).toBe("Se connecter");
    expect(host.querySelector("details summary")?.textContent).toBe("Autres méthodes de connexion");
    await i18n.changeLanguage("en");
  });
});
