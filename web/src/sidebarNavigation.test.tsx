// @vitest-environment jsdom
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";
import { useNavigate } from "react-router-dom";
import { activeSidebarGroup, SidebarNavigation, sidebarNavigationForRole } from "./App";
import { i18n, setLocale } from "./i18n";

let root: Root | undefined;
let host: HTMLDivElement | undefined;
;(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function RouteControls() {
  const navigate = useNavigate();
  return createElement("div", null,
    createElement("button", { type: "button", onClick: () => navigate("/system/users") }, "Go to users"),
    createElement("button", { type: "button", onClick: () => navigate(-1) }, "Back"),
  );
}

function renderNavigation(role = "ADMIN", path = "/") {
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
  act(() => {
    root!.render(createElement(MemoryRouter, { initialEntries: [path], future: { v7_startTransition: true, v7_relativeSplatPath: true } },
      createElement("div", null, createElement(SidebarNavigation, { role }), createElement(RouteControls))));
  });
  return host;
}

afterEach(() => {
  if (root) act(() => root!.unmount());
  host?.remove();
  root = undefined;
  host = undefined;
});

describe("Aurora sidebar navigation", () => {
  it("preserves the sections, order, links and role-based visibility", () => {
    expect(sidebarNavigationForRole("ADMIN").map(({ heading }) => heading)).toEqual([
      null, "ACCESS & REFERENCE", "AUDIT", "SYSTEM",
    ]);
    expect(sidebarNavigationForRole("ADMIN").flatMap(({ items }) => items.map(({ to }) => to))).toEqual([
      "/", "/reviews", "/perimeters", "/identities", "/accesses", "/golden", "/campaigns", "/findings",
      "/actions", "/reports", "/sources", "/system/users", "/system/authentication", "/system/audit",
    ]);
    const paths = (role: string) => sidebarNavigationForRole(role).flatMap(({ items }) => items.map(({ to }) => to));
    expect(paths("OPERATOR")).toEqual([
      "/", "/reviews", "/perimeters", "/identities", "/accesses", "/golden", "/campaigns", "/findings",
      "/actions", "/reports", "/sources",
    ]);
    expect(paths("GROUP_OWNER")).toEqual(["/reviews"]);
    expect(paths("REMEDIATION_MANAGER")).toEqual(["/actions"]);
    expect(paths("BUSINESS_ADMIN")).toEqual(["/actions"]);
  });

  it("opens the active group on direct and nested routes and follows route history changes", () => {
    expect(activeSidebarGroup("/identities", "ADMIN")).toBe("ACCESS & REFERENCE");
    expect(activeSidebarGroup("/campaigns/c-1", "ADMIN")).toBe("AUDIT");
    expect(activeSidebarGroup("/sources/source-1/browse", "ADMIN")).toBe("SYSTEM");
    expect(activeSidebarGroup("/system/users", "OPERATOR")).toBeNull();
    const host = renderNavigation("ADMIN", "/campaigns/c-1");
    const nav = host.querySelector("nav")!;
    const audit = nav.querySelector<HTMLButtonElement>('button[aria-controls="aurora-nav-audit"]')!;
    expect(audit.getAttribute("aria-expanded")).toBe("true");
    expect(audit.getAttribute("aria-controls")).toBe("aurora-nav-audit");
    expect(nav.querySelector<HTMLAnchorElement>('a[href="/campaigns"]')?.getAttribute("aria-current")).toBe("page");
    act(() => host.querySelector<HTMLButtonElement>('button:not([aria-controls])')!.click());
    expect(nav.querySelector<HTMLButtonElement>('button[aria-controls="aurora-nav-system"]')?.getAttribute("aria-expanded")).toBe("true");
    act(() => host.querySelectorAll<HTMLButtonElement>('button:not([aria-controls])')[1].click());
    expect(nav.querySelector<HTMLButtonElement>('button[aria-controls="aurora-nav-audit"]')?.getAttribute("aria-expanded")).toBe("true");
  });

  it("keeps one accordion group open at a time and supports keyboard-focusable native buttons", () => {
    const nav = renderNavigation().querySelector("nav")!;
    const access = nav.querySelector<HTMLButtonElement>('button[aria-controls="aurora-nav-access-reference"]')!;
    const audit = nav.querySelector<HTMLButtonElement>('button[aria-controls="aurora-nav-audit"]')!;
    expect(access.type).toBe("button");
    expect(access.tabIndex).toBe(0);
    expect(access.getAttribute("aria-expanded")).toBe("false");
    act(() => access.click());
    expect(access.getAttribute("aria-expanded")).toBe("true");
    expect(nav.querySelector("#aurora-nav-access-reference")?.hasAttribute("hidden")).toBe(false);
    act(() => audit.click());
    expect(access.getAttribute("aria-expanded")).toBe("false");
    expect(audit.getAttribute("aria-expanded")).toBe("true");
    act(() => audit.click());
    expect(audit.getAttribute("aria-expanded")).toBe("false");
    expect(nav.querySelector("#aurora-nav-audit")?.hasAttribute("hidden")).toBe(true);
  });

  it("keeps the current locale and hides unavailable groups", async () => {
    await setLocale("en");
    const english = renderToStaticMarkup(createElement(MemoryRouter, null, createElement(SidebarNavigation, { role: "ADMIN" })));
    expect(english).toContain("Access &amp; reference");
    await setLocale("fr");
    const french = renderToStaticMarkup(createElement(MemoryRouter, null, createElement(SidebarNavigation, { role: "ADMIN" })));
    expect(french).toContain(i18n.t("nav.accessReference").replace("&", "&amp;"));
    const restricted = renderToStaticMarkup(createElement(MemoryRouter, null, createElement(SidebarNavigation, { role: "GROUP_OWNER" })));
    expect(restricted).toContain(i18n.t("nav.myReviews"));
    expect(restricted).not.toContain(i18n.t("nav.accessReference"));
    await setLocale("en");
  });
});
