import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Navigate, NavLink, Route, Routes, useParams } from "react-router-dom";
import {
  AlertTriangle,
  ArrowDown,
  ArrowLeft,
  Check,
  ChevronRight,
  Database,
  FileDown,
  KeyRound,
  Languages,
  LayoutDashboard,
  LogOut,
  Menu,
  ChevronDown,
  MoreHorizontal,
  Palette,
  Search,
  Settings,
  ShieldCheck,
  Users,
  X,
} from "lucide-react";
import { applyTheme, readTheme, storeTheme, THEMES, type ThemeId } from "./theme";
import { LOCALE_LABELS, SUPPORTED_LOCALES, i18n, setLocale, type Locale } from "./i18n";
import { useTranslation } from "react-i18next";
import {
  changePassword,
  deleteJson,
  getJson,
  getPage,
  getSession,
  login,
  logout,
  postDecision,
  postJson,
  patchJson,
  putJson,
  type Principal,
  type Row,
} from "./api/client";
import {
  campaignActionTarget,
  campaignCtas,
  pageCount,
  pageLabel,
  pendingFirst,
  roleHome,
  validProviderScope,
} from "./projections";
const s = (v: unknown, f = "—") =>
    v instanceof Error
      ? v.message
      : v == null || v === ""
        ? f
        : typeof v === "string" || typeof v === "number"
          ? String(v)
          : JSON.stringify(v),
  arr = (v: unknown): Row[] =>
    Array.isArray(v) ? v.filter((x): x is Row => !!x && typeof x === "object") : [],
  vals = (v: unknown) => (Array.isArray(v) ? v.map(String) : []),
  pct = (v: unknown) => Math.max(0, Math.min(100, Number(v) || 0));
const ui = (key: string, options?: Record<string, string | number>) => String(i18n.t(key, options as never));
const count = (rows: Row[], keep: (row: Row) => boolean) => rows.filter(keep).length;
const DEFAULT_GOLDEN_CAPABILITIES = ["read", "write", "delete", "execute", "approve", "admin", "grant"];
// The collectors store structured references; the WebUI must read them as a sentence.
const refText = (v: unknown): string => {
  if (typeof v === "string") return v;
  const row = (v ?? null) as Row | null;
  return row ? s(row.display_name, s(row.identifier, s(row.name, ""))) : "";
};
const permissionText = (v: unknown): string => refText(v);
const ownerDisplayLabel = (value: unknown, identities: Row[], fallbackProvider = ""): string => {
  const raw = typeof value === "string" ? value.trim() : refText(value).trim();
  if (!raw) return "";
  const parts = raw.split("/");
  const provider = parts.length > 1 ? parts.shift()!.trim() : fallbackProvider;
  const reference = parts.join("/").trim() || raw;
  const normalize = (candidate: string) => candidate.replace(/^entry:/i, "").trim().toLowerCase();
  const referenceForms = new Set([reference, raw, normalize(reference), normalize(raw)].filter(Boolean).map((item) => item.toLowerCase()));
  const identity = identities.find((row) => {
    if (provider && s(row.provider, "") !== provider) return false;
    return [s(row.identifier, ""), s(row.native_id, ""), s(row.id, "")]
      .filter(Boolean)
      .some((candidate) => referenceForms.has(candidate.toLowerCase()) || referenceForms.has(normalize(candidate)));
  });
  return identity ? `${s(identity.provider, provider)}/${s(identity.display_name, s(identity.identifier, s(identity.id)))}` : `${provider}/Unknown identity`;
};
const providerLabel = (provider: Row): string => {
  const name = s(provider.name),
    display = s(provider.display_name, name);
  return display === name ? name : `${display} · ${name}`;
};
const readableDetails = (value: unknown): string => {
  if (value == null || value === "") return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "string" || typeof value === "number") return String(value);
  if (Array.isArray(value)) return value.map(readableDetails).join(", ");
  if (typeof value === "object")
    return Object.entries(value as Row)
      .map(([key, item]) => `${key.replaceAll("_", " ")}: ${readableDetails(item)}`)
      .join(" · ");
  return String(value);
};
const targetText = (v: unknown): string => {
  const target = (v ?? null) as Row | null;
  if (!target) return "";
  return [refText(target.resource), refText(target.component), refText(target.service)]
    .filter(Boolean)
    .join(" · ");
};
const contextField = (context: unknown, field: string): Row => {
  const root = (context ?? {}) as Row;
  return ((((root.fields ?? {}) as Row)[field] ?? {}) as Row);
};
const contextValue = (context: unknown, field: string, origin: "source" | "manual"): string => {
  const value = contextField(context, field)[origin] as Row | undefined;
  return value ? s(value.value, "") : "";
};
function BusinessContext({ context, manualStatus }: { context: unknown; manualStatus?: string }) {
  const rows = [
    ["Application", "application"],
    ["Permission", "business_permission"],
    ["Resource", "resource"],
    ["Description", "description"],
    ["Owner", "owner"],
  ] as const;
  const visible = rows.filter(([, field]) => contextValue(context, field, "source") || contextValue(context, field, "manual"));
  if (!visible.length && manualStatus !== "not_captured") return <p className="muted">Business context not provided.</p>;
  return (
    <>
      {visible.length ? <div className="business-context">
        {visible.map(([label, field]) => {
          const source = contextValue(context, field, "source"),
            manual = contextValue(context, field, "manual"),
            conflict = Boolean(contextField(context, field).conflict),
            sourceEntry = contextField(context, field).source as Row | undefined;
          return (
            <div key={field}>
              <strong>{label}</strong>
              {manual ? <span>{manual}<small>Manual reference</small></span> : null}
              {source ? <span>{source}<small>{sourceEntry?.provenance === "static" ? "Configured static" : sourceEntry?.provenance === "native_semantic" ? "Native semantic" : `Source attribute${sourceEntry?.attribute ? `: ${s(sourceEntry.attribute)}` : ""}${sourceEntry?.mapping_mode === "default" ? " · connector default" : sourceEntry?.mapping_mode === "configured" ? " · configured mapping" : ""}`}</small></span> : null}
              {conflict ? <Status v="warning" /> : null}
            </div>
          );
        })}
      </div> : null}
      {manualStatus === "not_captured" ? <p className="form-error">Manual context was not captured when this campaign opened, so no current catalogue value is shown as historical evidence.</p> : null}
    </>
  );
}
/** What this access lets someone do, in words: the collected description, or permission on target. */
const describeAccess = (row: Row): string => {
  const described = s(row.description, "");
  if (described) return described;
  const permission = permissionText(row.permission),
    target = targetText(row.target);
  if (permission.toLowerCase() === "member") return "Group membership";
  if (permission && target) return `${permission} on ${target}`;
  return permission || target || "";
};
const describeIdentity = (row: Row): string =>
  [s(row.display_name, ""), s(row.description, ""), s(row.email, "")].filter(Boolean).join(" · ");
const Sub = ({ children }: { children: ReactNode }) =>
  children ? <span className="cell-sub">{children}</span> : null;
type Notice = { id: number; tone: "ok" | "error"; text: string };
const ToastContext = createContext<(tone: "ok" | "error", text: string) => void>(() => {});
const useToast = () => useContext(ToastContext);
/** Reports what an action did, so a click never fails in silence. */
function Toasts({ children }: { children: ReactNode }) {
  const [notices, setNotices] = useState<Notice[]>([]);
  const push = (tone: "ok" | "error", text: string) => {
    const notice = { id: Date.now() + Math.random(), tone, text };
    setNotices((all) => [...all, notice]);
    if (tone === "ok") setTimeout(() => setNotices((all) => all.filter((x) => x.id !== notice.id)), 5000);
  };
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="toasts" aria-live="polite">
        {notices.map((notice) => (
          <div className={notice.tone === "ok" ? "toast" : "toast error"} key={notice.id}>
            <span>{notice.text}</span>
            <button
              className="icon-button"
              aria-label="Dismiss"
              onClick={() => setNotices((all) => all.filter((x) => x.id !== notice.id))}
            >
              <X size={15} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
function App() {
  useTranslation();
  const q = useQuery({ queryKey: ["session"], queryFn: getSession, retry: false });
  return q.isLoading ? (
    <div className="loading-page">{ui("common.loading")} EARE</div>
  ) : q.isError ? (
    <Login />
  ) : q.data!.must_change_password ? (
    <PasswordChange />
  ) : (
    <Toasts>
      <Shell principal={q.data!} />
    </Toasts>
  );
}
function AuthFrame({ children }: { children: ReactNode }) {
  return (
    <div className="login-page">
      <div className="auth-layout">
        <aside className="auth-intro">
          <div className="auth-product">
            <span className="auth-product-icon"><ShieldCheck size={22} strokeWidth={1.8} /></span>
            <span><strong>EARE</strong><small>Access Review Engine</small></span>
          </div>
          <div className="auth-message">
            <span className="auth-eyebrow">{ui("auth.accessGovernance")}</span>
            <h2>{ui("auth.everyAccess")}<br /><em>{ui("auth.accountedFor")}</em></h2>
            <p>{ui("auth.intro")}</p>
          </div>
          <div className="auth-process">
            <div><span>01</span><strong>{ui("auth.collect")}</strong><small>{ui("auth.knowCurrentState")}</small></div>
            <div><span>02</span><strong>{ui("auth.compare")}</strong><small>{ui("auth.findAttention")}</small></div>
            <div><span>03</span><strong>{ui("auth.certify")}</strong><small>{ui("auth.recordDecision")}</small></div>
          </div>
          <div className="auth-foot">{ui("auth.productBy")} <strong>LCIT Cybersecurity</strong></div>
        </aside>
        <div className="auth-form-wrap">
          <div className="auth-form-content">
            <div className="auth-company">
              <img src="/lcit-logo.png" alt="LCIT logo" />
              <div><strong>LCIT Cybersecurity</strong><span>{ui("auth.identityGovernance")}</span></div>
            </div>
            {children}
            <p className="auth-form-foot">{ui("auth.protectedWorkspace")}</p>
          </div>
        </div>
      </div>
    </div>
  );
}
function PasswordChange() {
  const c = useQueryClient(),
    [p, setP] = useState(""),
    [confirm, setConfirm] = useState(""),
    [visible, setVisible] = useState(false),
    [e, setE] = useState("");
  const m = useMutation({
    mutationFn: () => changePassword(p),
    onSuccess: (x) => c.setQueryData(["session"], x),
    onError: (x) => setE(s(x, "Unable to change password")),
  });
  return (
    <AuthFrame>
      <form
        className="login-card"
        onSubmit={(x) => {
          x.preventDefault();
          if (p !== confirm) {
            setE(ui("auth.passwordMismatch"));
            return;
          }
          setE("");
          m.mutate();
        }}
      >
        <span className="auth-eyebrow">{ui("auth.accountSecurity")}</span>
        <h1>{ui("auth.changePassword")}</h1>
        <p>{ui("auth.newPasswordContinue")}</p>
        <label>
          {ui("auth.newPassword")}
          <span className="password-field">
            <input required autoFocus autoComplete="new-password" minLength={12} type={visible ? "text" : "password"} value={p} onChange={(x) => setP(x.target.value)} />
            <button type="button" className="text-button" aria-label={visible ? "Hide password" : "Show password"} onClick={() => setVisible(!visible)}>
              {visible ? ui("common.hide") : ui("common.show")}
            </button>
          </span>
        </label>
        <label>
          {ui("auth.confirmPassword")}
          <input
            required
            autoComplete="new-password"
            minLength={12}
            type={visible ? "text" : "password"}
            value={confirm}
            onChange={(x) => setConfirm(x.target.value)}
          />
        </label>
        {e && <p className="form-error" role="alert">{e}</p>}
        <button className="button primary" disabled={m.isPending}>
          {m.isPending ? ui("auth.changing") : ui("auth.change")}
        </button>
      </form>
    </AuthFrame>
  );
}
const SIGNED_OUT_KEY = "eare.signed-out";
function markSignedOut() {
  try {
    window.sessionStorage.setItem(SIGNED_OUT_KEY, "1");
  } catch {
    // A browser that refuses storage simply shows no confirmation.
  }
}
function takeSignedOut(): boolean {
  try {
    if (window.sessionStorage.getItem(SIGNED_OUT_KEY) !== "1") return false;
    window.sessionStorage.removeItem(SIGNED_OUT_KEY);
    return true;
  } catch {
    return false;
  }
}
function Login() {
  const c = useQueryClient(),
    [u, setU] = useState(""),
    [p, setP] = useState(""),
    [visible, setVisible] = useState(false),
    [signedOut, setSignedOut] = useState(takeSignedOut),
    [e, setE] = useState("");
  const m = useMutation({
    mutationFn: () => login(u, p),
    onSuccess: (x) => c.setQueryData(["session"], x),
    onError: (x) => setE(s(x, "Unable to sign in")),
  });
  return (
    <AuthFrame>
      <form
        className="login-card"
        onSubmit={(x) => {
          x.preventDefault();
          setE("");
          setSignedOut(false);
          m.mutate();
        }}
      >
        <span className="auth-eyebrow">{ui("auth.welcomeBack").toUpperCase()}</span>
        <h1>{ui("auth.welcomeBack")}</h1>
        <p>{ui("auth.signInContinue")}</p>
        <label>
          {ui("auth.username")}
          <input
            required
            autoFocus
            autoComplete="username"
            value={u}
            onChange={(x) => setU(x.target.value)}
          />
        </label>
        <label>
          {ui("auth.password")}
          <span className="password-field">
            <input
              required
              autoComplete="current-password"
              type={visible ? "text" : "password"}
              value={p}
              onChange={(x) => setP(x.target.value)}
            />
            <button
              type="button"
              className="text-button"
              aria-label={visible ? "Hide password" : "Show password"}
              onClick={() => setVisible(!visible)}
            >
              {visible ? ui("common.hide") : ui("common.show")}
            </button>
          </span>
        </label>
        {signedOut && !e ? (
          <p className="form-notice" role="status">
            <Check size={15} /> {ui("auth.signedOut")}
          </p>
        ) : null}
        {e && <p className="form-error" role="alert">{e}</p>}
        <button className="button primary" disabled={m.isPending}>
          {m.isPending ? ui("auth.signingIn") : ui("auth.signIn")}
        </button>
      </form>
    </AuthFrame>
  );
}
const NAV_KEYS: Record<string, string> = {
  "Overview": "nav.overview", "My Reviews": "nav.myReviews", "My Actions": "nav.myActions",
  "ACCESS & REFERENCE": "nav.accessReference", Identities: "nav.identities", Access: "nav.access", "Golden Source": "nav.golden",
  AUDIT: "nav.audit", Campaigns: "nav.campaigns", Findings: "nav.findings", Actions: "nav.actions", Reports: "nav.reports",
  SYSTEM: "nav.system", "Sources & IdPs": "nav.sources", "Users & permissions": "nav.usersPermissions",
  Authentication: "nav.authentication", "Audit trail": "nav.auditTrail",
};
const UI_LABEL_KEYS: Record<string, string> = {
  ...NAV_KEYS,
  "Expected access rights": "golden.expectedAccessRights", "Who holds them": "golden.whoHoldsThem",
  "Changes since the last collection": "golden.changesSinceLastCollection", "Authentication policy": "golden.authenticationPolicy",
  "Version history": "golden.versionHistory", "Access right": "golden.accessRight", Type: "golden.type", Target: "golden.target",
  "Effective rights": "golden.effectiveRights", Owner: "golden.owner", Source: "golden.source", Model: "golden.model",
  "Expected holders": "golden.expectedHolders", Comment: "golden.comment", Application: "golden.application",
  Permission: "golden.permission", Resource: "golden.resource", Description: "golden.description",
  Save: "common.save", Cancel: "common.cancel", Close: "common.close", Edit: "common.edit", Delete: "common.delete",
  Add: "common.add", Remove: "common.remove", Search: "common.search", Loading: "common.loading",
  Approve: "campaign.approve", Revoke: "campaign.revoke", "Not applicable": "campaign.notApplicable",
  Campaign: "labels.campaign", Scope: "labels.scope", Status: "labels.status", Progress: "labels.progress",
  Pending: "labels.pending", "Due date": "labels.dueDate", Identity: "labels.identity", Access: "labels.access",
  State: "labels.state", Decision: "labels.decision", Reason: "labels.reason", Reviewer: "labels.reviewer", Provider: "labels.provider",
  Findings: "labels.findings", Reviews: "labels.reviews", Decided: "labels.decided",
  Classification: "labels.classification", Observed: "labels.observed", Expected: "labels.expected",
  "Requested action": "labels.requestedAction", "Access / Application": "labels.accessApplication", Action: "labels.action",
  Accesses: "labels.accesses", "Source / IdP": "labels.sourceIdp", Mode: "labels.mode", "Direct / Effective": "labels.directEffective",
  Why: "labels.why", "Latest decision": "labels.latestDecision", Decide: "labels.decide", Finding: "labels.finding", Change: "labels.change",
  "Golden comment": "labels.goldenComment", Control: "labels.control", Assessment: "labels.assessment", "Golden usage": "labels.goldenUsage",
  Version: "labels.version", Origin: "labels.origin", Created: "labels.created", When: "labels.when", Actor: "labels.actor", Event: "labels.event",
  Object: "labels.object", Details: "labels.details", User: "labels.user", Username: "labels.username", "Signs in with": "labels.signsInWith",
  Role: "labels.role", "Authorized domains": "labels.authorizedDomains", "API access": "labels.apiAccess", "Pending reviews": "labels.pendingReviews",
  Person: "labels.person", Login: "labels.login", Email: "labels.email",
  "Still waiting": "labels.stillWaiting", "Review items": "labels.reviewItems", "Observed snapshot": "labels.observedSnapshot",
  "Expected state": "labels.expectedState", "Open campaign": "labels.openCampaign", "Close campaign": "labels.closeCampaign",
  Prepare: "labels.prepare", Review: "labels.review", Closed: "labels.closed", Remediation: "labels.remediation",
  Report: "labels.report", "Update baseline": "labels.updateBaseline",
  "No campaign yet": "ui.noCampaignYet", "Create a campaign": "ui.createCampaign", "Hide report": "ui.hideReport", "View report": "ui.viewReport",
  "Download HTML": "ui.downloadHtml", "Download CSV": "ui.downloadCsv", "Download JSON": "ui.downloadJson", "Download PDF": "ui.downloadPdf",
  "Open full report": "ui.openFullReport", "Final campaign report": "ui.finalCampaignReport", "Governance evidence": "ui.governanceEvidence",
  "Actions to implement": "ui.actionsToImplement", "Operational follow-up": "ui.operationalFollowUp", "Open campaigns": "dashboard.openCampaigns",
  "Reviews waiting": "dashboard.reviewsWaiting", "Remediation actions": "dashboard.remediationActions", "in progress": "dashboard.inProgress",
  "to be decided": "dashboard.toBeDecided", "to carry out": "dashboard.toCarryOut", "Your reviews": "dashboard.yourReviews",
  "Open my queue": "dashboard.openMyQueue", "Needs attention": "dashboard.needsAttention", "Campaigns in progress": "dashboard.campaignsInProgress",
  "No results": "common.noResults", "No reviews assigned": "ui.noReviewsAssigned", "No campaign is open": "ui.noCampaignOpen",
};
const uiLabel = (value: string) => UI_LABEL_KEYS[value] ? ui(UI_LABEL_KEYS[value]) : value;


const navSections = [
  {
    heading: null,
    items: [
      { to: "/", label: "Overview", icon: LayoutDashboard, roles: ["ADMIN", "OPERATOR"] },
      { to: "/reviews", label: "My Reviews", icon: Check, roles: ["ADMIN", "OPERATOR", "GROUP_OWNER"] },
      {
        to: "/actions?view=my",
        label: "My Actions",
        icon: Check,
        roles: ["ADMIN", "OPERATOR", "BUSINESS_ADMIN"],
      },
    ],
  },
  {
    heading: "ACCESS & REFERENCE",
    items: [
      { to: "/identities", label: "Identities", icon: Users, roles: ["ADMIN", "OPERATOR"] },
      { to: "/accesses", label: "Access", icon: KeyRound, roles: ["ADMIN", "OPERATOR"] },
      { to: "/golden", label: "Golden Source", icon: ShieldCheck, roles: ["ADMIN", "OPERATOR"] },
    ],
  },
  {
    heading: "AUDIT",
    items: [
      { to: "/campaigns", label: "Campaigns", icon: Check, roles: ["ADMIN", "OPERATOR"] },
      { to: "/findings", label: "Findings", icon: AlertTriangle, roles: ["ADMIN", "OPERATOR"] },
      { to: "/actions", label: "Actions", icon: Check, roles: ["ADMIN", "OPERATOR", "BUSINESS_ADMIN", "REMEDIATION_MANAGER"] },
      { to: "/reports", label: "Reports", icon: FileDown, roles: ["ADMIN", "OPERATOR"] },
    ],
  },
  {
    heading: "SYSTEM",
    items: [
      { to: "/sources", label: "Sources & IdPs", icon: Database, roles: ["ADMIN", "OPERATOR"] },
      { to: "/system/users", label: "Users & permissions", icon: Users, roles: ["ADMIN"] },
      { to: "/system/authentication", label: "Authentication", icon: Settings, roles: ["ADMIN"] },
      { to: "/system/audit", label: "Audit trail", icon: FileDown, roles: ["ADMIN"] },
    ],
  },
];
function Shell({ principal }: { principal: Principal }) {
  const [c, setC] = useState(false);
  return (
    <div className="app-shell">
      <aside className={c ? "sidebar open" : "sidebar"}>
        <div className="brand">
          <img className="brand-logo" src="/lcit-logo.png" alt="LCIT Cybersecurity" />
          <div>
            <span>EARE</span>
            <small>Access governance</small>
          </div>
        </div>
        <nav>
          {navSections.map((section) => {
            const items = section.items.filter((x) => x.roles.includes(principal.role));
            return items.length ? (
              <div className="nav-section" key={section.heading ?? "product"}>
                {section.heading && <div className="nav-heading">{ui(NAV_KEYS[section.heading] ?? section.heading)}</div>}
                {items.map(({ to, label, icon: I }) => (
                  <NavLink
                    key={to}
                    to={to}
                    end={to === "/"}
                    onClick={() => setC(false)}
                    className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
                  >
                    <I size={17} />
                    {ui(NAV_KEYS[label] ?? label)}
                  </NavLink>
                ))}
              </div>
            ) : null;
          })}
        </nav>
        <div className="sidebar-footer">
          {ui("auth.productBy")} <strong>LCIT Cybersecurity</strong>
        </div>
      </aside>
      <div className="page">
        <header className="topbar">
          <button className="icon-button mobile-menu" onClick={() => setC(!c)}>
            <Menu />
          </button>
          <span className="crumb">
            {ui("nav.workspace")} <ChevronRight size={14} /> {ui("nav.accessGovernance")}
          </span>
          <div className="top-actions">
            <UserMenu
              principal={principal}
              onSignOut={async () => {
                await logout().catch(() => {});
                markSignedOut();
                // Dropping the session query alone leaves every other cached page holding
                // the previous account's data, and react-query does not necessarily refetch
                // a removed query. A reload is both the correct state and the safe one.
                window.location.assign("/");
              }}
            />
          </div>
        </header>
        <main>
          <Routes>
            <Route
              path="/"
              element={
                roleHome(principal.role) === "/" ? <Home /> : <Navigate to={roleHome(principal.role)} replace />
              }
            />
            <Route path="/reviews" element={<Reviews />} />
            <Route path="/identities" element={<Identities />} />
            <Route path="/accesses" element={<Accesses />} />
            <Route path="/golden" element={<Golden />} />
            <Route path="/campaigns" element={<Campaigns />} />
            <Route path="/campaigns/new" element={<CampaignNew principal={principal} />} />
            <Route path="/campaigns/:id/edit" element={<CampaignNew principal={principal} />} />
            <Route path="/campaigns/:id" element={<CampaignDetail />} />
            <Route path="/findings" element={<List path="findings" title="Findings" />} />
            <Route path="/actions" element={<List path="remediation-actions" title="Actions" />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/sources" element={<Sources principal={principal} />} />
            <Route path="/sources/:provider/browse" element={<SourceBrowser />} />
            <Route path="/system/users" element={<UsersPage />} />
            <Route path="/system/authentication" element={<Auth />} />
            <Route path="/system/audit" element={<AuditTrail />} />
            <Route path="*" element={<Navigate to={roleHome(principal.role)} />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
function Head({ title, subtitle, children }: { title: string; subtitle?: string; children?: ReactNode }) {
  return (
    <div className="page-header">
      <div>
        <div className="eyebrow">EARE</div>
        <h1>{uiLabel(title)}</h1>
        {subtitle ? <p className="page-subtitle">{subtitle}</p> : null}
      </div>
      {children}
    </div>
  );
}
// One vocabulary for every state the product shows, so a status reads the same everywhere.
const STATUS_LABELS: Record<string, string> = {
  expected_and_observed: "As expected",
  unexpected: "Not expected",
  missing: "Missing",
  no_reference: "No reference",
  unknown_due_to_scope: "Out of scope",
  pending: "Pending",
  approve: "Approved",
  revoke: "Revoked",
  not_applicable: "Not applicable",
  draft: "Draft",
  open: "Open",
  closed: "Closed",
  cancelled: "Cancelled",
  healthy: "Healthy",
  failed: "Failed",
  never_synced: "Never collected",
  enabled: "Active",
  disabled: "Disabled",
  exported: "Exported",
  added: "To add",
  removed: "No longer present",
  unchanged: "Unchanged",
  active: "Active",
  deleted: "Deleted",
  unknown: "Unknown",
  ACTIVE: "Active",
  DISABLED: "Disabled",
  NOT_YET_ACTIVE: "Not yet active",
  ADMIN: "Admin",
  OPERATOR: "Operator",
  GROUP_OWNER: "Group owner",
  BUSINESS_ADMIN: "Business admin",
  REMEDIATION_MANAGER: "Remediation manager",
  QUEUED: "Queued",
  RUNNING: "Running",
  SUCCEEDED: "Completed",
  FAILED: "Failed",
};
const STATUS_TONES: Record<string, string> = {
  expected_and_observed: "ok",
  approve: "ok",
  healthy: "ok",
  enabled: "ok",
  active: "ok",
  ACTIVE: "ok",
  SUCCEEDED: "ok",
  unchanged: "ok",
  exported: "ok",
  unexpected: "bad",
  revoke: "bad",
  failed: "bad",
  FAILED: "bad",
  disabled: "bad",
  DISABLED: "bad",
  deleted: "bad",
  removed: "bad",
  missing: "warn",
  pending: "warn",
  draft: "warn",
  never_synced: "warn",
  QUEUED: "warn",
  no_reference: "warn",
  open: "info",
  RUNNING: "info",
  added: "info",
};
function Status({ v }: { v: unknown }) {
  const raw = s(v, "unknown"),
    label = ui(`status.${raw}`, { defaultValue: STATUS_LABELS[raw] ?? raw.replaceAll("_", " ") }),
    tone = STATUS_TONES[raw] ?? "neutral";
  return (
    <span className={`badge ${tone}`}>
      <span className="dot" />
      {label}
    </span>
  );
}
function expectedMeaning(row: Row): string {
  const classification = s(row.classification, "");
  if (classification === "no_reference" || classification === "unknown_due_to_scope") return ui("ui.expectedNotDetermined", { defaultValue: "Non déterminé" });
  return row.expected ? ui("ui.accessExpected", { defaultValue: "Oui" }) : ui("ui.accessNotExpected", { defaultValue: "Non" });
}
function observedMeaning(row: Row): string {
  return row.observed ? ui("ui.accessObserved", { defaultValue: "Présent" }) : ui("ui.accessNotObserved", { defaultValue: "Absent" });
}
function Filter({
  v,
  onChange,
  children,
}: {
  v: string;
  onChange: (v: string) => void;
  children?: ReactNode;
}) {
  return (
    <div className="filterbar">
      <div className="search">
        <Search />
        <input placeholder={ui("common.search")} value={v} onChange={(e) => onChange(e.target.value)} />
      </div>
      {children}
    </div>
  );
}
function SelectFilter({
  value,
  onChange,
  options,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  options: string[];
  placeholder: string;
}) {
  return (
    <select className="filter-button" value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">{uiLabel(placeholder)}</option>
      {options.map((x) => (
        <option key={x} value={x}>
          {x.replaceAll("_", " ")}
        </option>
      ))}
    </select>
  );
}
function ProviderFilter({
  value,
  onChange,
  placeholder = "Source / application",
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}) {
  const q = useQuery({ queryKey: ["provider-options"], queryFn: () => getPage("providers", { limit: 500 }) });
  return (
    <select className="filter-button" value={value} onChange={(event) => onChange(event.target.value)}>
      <option value="">{uiLabel(placeholder)}</option>
      {arr(q.data?.items).map((provider) => (
        <option key={s(provider.name)} value={s(provider.name)}>
          {providerLabel(provider)}
        </option>
      ))}
    </select>
  );
}
function CampaignFilter({
  value,
  onChange,
  campaigns,
}: {
  value: string;
  onChange: (value: string) => void;
  campaigns: Row[];
}) {
  return (
    <select className="filter-button" value={value} onChange={(event) => onChange(event.target.value)}>
      <option value="">{uiLabel("Campaign")}</option>
      {campaigns.map((campaign) => (
        <option key={s(campaign.id)} value={s(campaign.id)}>
          {s(campaign.display_name, s(campaign.name, s(campaign.id)))}
        </option>
      ))}
    </select>
  );
}
function debounce(v: string) {
  const [d, setD] = useState(v);
  useEffect(() => {
    const x = setTimeout(() => setD(v), 300);
    return () => clearTimeout(x);
  }, [v]);
  return d;
}
function Pager({
  total,
  limit,
  offset,
  setOffset,
  setLimit,
}: {
  total: number;
  limit: number;
  offset: number;
  setOffset: (n: number) => void;
  setLimit: (n: number) => void;
}) {
  const pages = pageCount(total, limit),
    p = Math.floor(offset / limit) + 1;
  return (
    <div className="pagination">
      <span>{pageLabel(total, limit, offset)}</span>
      <button className="button subtle" disabled={p <= 1} onClick={() => setOffset(offset - limit)}>
        {ui("common.previous")}
      </button>
      <span>
        {ui("common.page")} {p} / {pages}
      </span>
      <button className="button subtle" disabled={p >= pages} onClick={() => setOffset(offset + limit)}>
        {ui("common.next")}
      </button>
      <select
        value={limit}
        onChange={(e) => {
          setLimit(+e.target.value);
          setOffset(0);
        }}
      >
        <option>25</option>
        <option>50</option>
        <option>100</option>
      </select>
    </div>
  );
}
type SortState = { sort: string; order: string; toggle: (field: string) => void };
type FilterState = { values: Row; set: (field: string, value: string) => void };
/** A column header that sorts and filters from one menu, the way a spreadsheet does. */
function ColumnMenu({
  label,
  field,
  sorting,
  filtering,
}: {
  label: string;
  field: string;
  sorting?: SortState;
  filtering?: FilterState;
}) {
  const [open, setOpen] = useState(false),
    active = sorting?.sort === field,
    filtered = s(filtering?.values[field], ""),
    sortAs = (want: string) => {
      if (!sorting) return;
      if (sorting.sort !== field) sorting.toggle(field);
      if (sorting.sort === field && sorting.order !== want) sorting.toggle(field);
      setOpen(false);
    };
  return (
    <div className="column-menu">
      <button
        className={active || filtered ? "sort-button active" : "sort-button"}
        onClick={() => setOpen(!open)}
        aria-label={ui("table.sortOrFilter", { label })}
      >
        {label}
        <span>{active ? (sorting!.order === "desc" ? "▼" : "▲") : filtered ? "▣" : "▾"}</span>
      </button>
      {open ? (
        <>
          <div className="menu-backdrop" onClick={() => setOpen(false)} />
          <div className="menu-panel">
            {sorting ? (
              <div className="menu-row">
                <button className="text-button" onClick={() => sortAs("asc")}>
                  {ui("table.sortAZ")}
                </button>
                <button className="text-button" onClick={() => sortAs("desc")}>
                  {ui("table.sortZA")}
                </button>
              </div>
            ) : null}
            {filtering ? (
              <>
                <input
                  autoFocus
                  placeholder={ui("table.filter", { label: label.toLowerCase() })}
                  value={filtered}
                  onChange={(e) => filtering.set(field, e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && setOpen(false)}
                />
                <div className="menu-row">
                  <button className="text-button" onClick={() => filtering.set(field, "")}>
                    Clear filter
                  </button>
                  <button className="text-button" onClick={() => setOpen(false)}>
                    Done
                  </button>
                </div>
              </>
            ) : null}
          </div>
        </>
      ) : null}
    </div>
  );
}
function initials(name: string) {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  const letters = parts.length > 1 ? parts[0][0] + parts[parts.length - 1][0] : name.slice(0, 2);
  return letters.toUpperCase();
}
// The account block doubles as the settings entry: the style is a per-viewer preference, so
// it belongs next to the viewer rather than in the product navigation.
function ApiTokenPanel({ menuOpen }: { menuOpen: boolean }) {
  const client = useQueryClient();
  const [issuedKey, setIssuedKey] = useState("");
  useEffect(() => {
    if (!menuOpen) setIssuedKey("");
  }, [menuOpen]);
  const status = useQuery({ queryKey: ["my-api-token"], queryFn: () => getJson("me/api-token") });
  const issue = useMutation({
    mutationFn: () => postJson("me/api-token"),
    onSuccess: async (result) => {
      setIssuedKey(s(result.api_key, ""));
      await client.invalidateQueries({ queryKey: ["my-api-token"] });
    },
  });
  const revoke = useMutation({
    mutationFn: () => deleteJson("me/api-token"),
    onSuccess: async () => {
      setIssuedKey("");
      await client.invalidateQueries({ queryKey: ["my-api-token"] });
    },
  });
  const token = (status.data?.token ?? {}) as Row;
  const authorized = Boolean(status.data?.api_access_enabled),
    globallyEnabled = Boolean(status.data?.external_user_api_enabled);
  return (
    <div className="user-menu-section">
      <span className="user-menu-label"><KeyRound size={13} /> API access</span>
      {status.isLoading ? <small className="muted">Loading API key status…</small> : null}
      {!status.isLoading && !authorized ? <small className="muted">API access is disabled by an administrator.</small> : null}
      {!status.isLoading && authorized && !globallyEnabled ? <small className="muted">External API is currently disabled.</small> : null}
      {authorized && globallyEnabled ? (
        <>
          {token.active ? (
            <small className="muted">
              {s(token.prefix)} · created {s(token.created_at)} · expires {s(token.expires_at)} · last used {s(token.last_used_at, "never")}
            </small>
          ) : <small className="muted">No active API key.</small>}
          {issuedKey ? (
            <div className="api-key-once">
              <strong>Copy this key now. It will not be displayed again.</strong>
              <code>{issuedKey}</code>
              <button className="button subtle" type="button" onClick={() => { if (navigator.clipboard) void navigator.clipboard.writeText(issuedKey); }}>Copy key</button>
            </div>
          ) : null}
          {(issue.error || revoke.error) ? <small className="form-error">{s(issue.error || revoke.error)}</small> : null}
          <div className="button-row">
            <button className="button subtle" type="button" disabled={issue.isPending} onClick={() => issue.mutate()}>
              {token.active ? "Generate new API key" : "Generate API key"}
            </button>
            {token.active ? <button className="button subtle" type="button" disabled={revoke.isPending} onClick={() => revoke.mutate()}>Revoke key</button> : null}
          </div>
          {token.active ? <small className="muted">Generating a new key immediately revokes the current key.</small> : null}
        </>
      ) : null}
    </div>
  );
}

function UserMenu({ principal, onSignOut }: { principal: Principal; onSignOut: () => void }) {
  const menu = useRef<HTMLDetailsElement>(null);
  const [theme, setTheme] = useState<ThemeId>(readTheme);
  const [menuOpen, setMenuOpen] = useState(false);
  const close = () => menu.current?.removeAttribute("open");
  const pick = (next: ThemeId) => {
    setTheme(next);
    applyTheme(next);
    storeTheme(next);
  };
  return (
    <details className="user-menu" ref={menu} onToggle={(event) => setMenuOpen(event.currentTarget.open)}>
      <summary aria-label="Account and settings">
        <span className="avatar">{initials(principal.display_name)}</span>
        <span className="user-name">
          {principal.display_name}
          <span>{principal.role}</span>
        </span>
        <ChevronDown size={15} />
      </summary>
      <div className="user-menu-panel">
        <div className="user-menu-head">
          <span className="avatar">{initials(principal.display_name)}</span>
          <span>
            <strong>{principal.display_name}</strong>
            <small>{principal.role}</small>
          </span>
        </div>
        <ApiTokenPanel menuOpen={menuOpen} />
        <div className="user-menu-section">
          <span className="user-menu-label">
            <Palette size={13} /> {ui("settings.settings")}
          </span>
          <label className="setting-option">
            <Languages size={16} />
            <span className="style-option-text">
              <strong>{ui("settings.language")}</strong>
              <small>{ui("settings.selectLanguage")}</small>
            </span>
            <select
              aria-label={ui("settings.selectLanguage")}
              value={(SUPPORTED_LOCALES as readonly string[]).includes(i18n.language) ? i18n.language : "en"}
              onChange={(event) => void setLocale(event.target.value)}
            >
              {SUPPORTED_LOCALES.map((locale: Locale) => <option key={locale} value={locale}>{LOCALE_LABELS[locale]}</option>)}
            </select>
          </label>
          {THEMES.map((option) => (
            <button
              className={"style-option" + (theme === option.id ? " active" : "")}
              key={option.id}
              type="button"
              aria-pressed={theme === option.id}
              onClick={() => pick(option.id)}
            >
              <span className={"style-swatch " + option.id} />
              <span className="style-option-text">
                <strong>{option.name}</strong>
                <small>{option.summary}</small>
              </span>
              {theme === option.id ? <Check size={15} /> : null}
            </button>
          ))}
        </div>
        <div className="user-menu-foot">
          <button
            type="button"
            onClick={() => {
              close();
              onSignOut();
            }}
          >
            <LogOut size={15} /> {ui("common.signOut", { defaultValue: "Sign out" })}
          </button>
        </div>
      </div>
    </details>
  );
}
export function ActionMenu({
  label,
  actions,
}: {
  label: string;
  actions: { label: string; onClick: () => void; danger?: boolean }[];
}) {
  const menu = useRef<HTMLDetailsElement>(null);
  return (
    <details className="action-menu" ref={menu}>
      <summary aria-label={label} title={label}>
        <MoreHorizontal size={18} />
      </summary>
      <div className="action-menu-panel">
        {actions.map((action) => (
          <button
            className={action.danger ? "danger" : ""}
            key={action.label}
            onClick={() => {
              menu.current?.removeAttribute("open");
              action.onClick();
            }}
          >
            {action.label}
          </button>
        ))}
      </div>
    </details>
  );
}
function Table({
  cols,
  rows,
  q,
  onRow,
  fields,
  sorting,
  filtering,
  emptyTitle = "No results",
  emptyText = "No record matches the current search and filters.",
  className = "",
}: {
  cols: string[];
  rows: ReactNode[][];
  q?: any;
  onRow?: (i: number) => void;
  /** Column index → API field name. Only the named columns become sortable and filterable. */
  fields?: (string | null)[];
  sorting?: SortState;
  filtering?: FilterState;
  emptyTitle?: string;
  emptyText?: string;
  className?: string;
}) {
  if (q?.isLoading)
    return (
      <div className={`table-wrap ${className}`}>
        <div className="empty">{ui("common.loading")}</div>
      </div>
    );
  if (q?.isError)
    return (
      <div className="table-wrap">
        <div className="empty">
          <strong>{s(q.error)}</strong>
          <button className="button subtle" onClick={() => q.refetch()}>
            {ui("common.retry")}
          </button>
        </div>
      </div>
    );
  return (
    <div className={`table-wrap ${className}`}>
      <table>
        <thead>
          <tr>
            {cols.map((x, i) => {
              const field = fields ? fields[i] : null;
              if (!field || (!sorting && !filtering)) return <th key={x}>{uiLabel(x)}</th>;
              return (
                <th key={x}>
                  <ColumnMenu label={uiLabel(x)} field={field} sorting={sorting} filtering={filtering} />
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {rows.length ? (
            rows.map((r, i) => (
              <tr className={onRow ? "clickable" : ""} onClick={(event) => { if (onRow && !(event.target as HTMLElement).closest("button,a,input,select,textarea")) onRow(i); }} key={i}>
                {r.map((x, j) => (
                  <td key={j}>{x}</td>
                ))}
              </tr>
            ))
          ) : (
            <tr className="empty-row">
              <td colSpan={cols.length}>
                <div className="empty">
                <strong>{uiLabel(emptyTitle)}</strong>
                <span>{uiLabel(emptyText)}</span>
                </div>
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
function Drawer({ title, close, children, size = "normal" }: { title: string; close: () => void; children: ReactNode; size?: "normal" | "wide" }) {
  const panel = useRef<HTMLElement>(null);
  // Callers pass an inline close; reading it through a ref keeps the effect below from
  // re-running on every render, which would pull focus out of the field being typed in.
  const closeRef = useRef(close);
  closeRef.current = close;
  useEffect(() => {
    const escape = (event: KeyboardEvent) => event.key === "Escape" && closeRef.current();
    document.addEventListener("keydown", escape);
    panel.current?.focus();
    return () => document.removeEventListener("keydown", escape);
  }, []);
  return (
    <div className="drawer-backdrop" onClick={close}>
      <aside
        aria-labelledby="drawer-title"
        aria-modal="true"
        className={`drawer drawer--${size}`}
        onClick={(e) => e.stopPropagation()}
        ref={panel}
        role="dialog"
        tabIndex={-1}
      >
        <div className="drawer-head">
          <h2 id="drawer-title">{title}</h2>
          <button aria-label="Close details" className="icon-button" onClick={close}>
            <X />
          </button>
        </div>
        <div className="drawer-body">{children}</div>
      </aside>
    </div>
  );
}
function AccessPath({
  direct,
  paths,
  identity,
}: {
  direct: boolean;
  paths: Row[];
  identity?: string;
}) {
  if (direct) return <div className="direct-grant">Direct grant</div>;
  if (!paths.length) return <p className="muted">Provenance unavailable</p>;
  return (
    <div className="access-paths">
      {paths.map((path, index) => {
        const chain = arr(path.steps ?? path.access_chain);
        const steps = [
          ...(identity ? [{ identifier: identity }] : []),
          ...chain,
        ];
        return (
          <div className="access-path" key={`${index}-${s(path.assignment_id, "path")}`}>
            {steps.map((step, stepIndex) => (
              <div className="access-path-step" key={`${stepIndex}-${s(step.identifier ?? step.name)}`}>
                {stepIndex ? <ArrowDown aria-hidden="true" size={14} /> : null}
                <span>{s(step.display_name, s(step.name, s(step.identifier)))}</span>
              </div>
            ))}
          </div>
        );
      })}
    </div>
  );
}
function SourceImpact({ result }: { result: Row }) {
  const objects = (result.objects ?? {}) as Row;
  const labels: Record<string, string> = {
    identities: "Identities",
    providers: "Sources",
    accesses: "Access rights",
    access_assignments: "Access assignments",
    access_relations: "Access relations",
  };
  const rows = Object.entries(objects)
    .filter(([, value]) => value && typeof value === "object")
    .map(([key, value]) => ({ key, counts: value as Row }));
  return (
    <div className="source-impact">
      <div className="source-impact-status">
        <Status v={result.collection_incomplete ? "unknown" : "healthy"} />
        <strong>{result.collection_incomplete ? "Collection incomplete" : "Collection complete"}</strong>
      </div>
      {rows.length ? (
        <div className="impact-grid">
          {rows.map(({ key, counts }) => (
            <div className="impact-card" key={key}>
              <strong>{labels[key] ?? key.replaceAll("_", " ")}</strong>
              <div>
                {Number(counts.added) ? <span className="impact-positive">+{s(counts.added)}</span> : null}
                {Number(counts.removed) ? <span className="impact-negative">−{s(counts.removed)}</span> : null}
                {Number(counts.updated) ? <span>{s(counts.updated)} updated</span> : null}
                {Number(counts.renamed) ? <span>{s(counts.renamed)} renamed</span> : null}
                {Number(counts.disabled) ? <span>{s(counts.disabled)} disabled</span> : null}
                {!Object.values(counts).some(Number) ? <span>No change</span> : null}
              </div>
            </div>
          ))}
        </div>
      ) : <p className="muted">No persisted object would change.</p>}
      {arr(result.access_preview).length ? (
        <section className="preview-accesses">
          <h3>Access and business context</h3>
          {arr(result.access_preview).slice(0, 20).map((access) => {
            const technical = (access.technical ?? {}) as Row,
              context = (access.business_context ?? {}) as Row;
            return (
              <article key={`${s(access.provider)}:${s(access.access_name)}`}>
                <strong>{s(access.display_name, s(access.access_name))}</strong>
                <small>{s(access.provider)} · {s(technical.grant_mechanism)} · technical permission {s(technical.permission)}</small>
                <BusinessContext context={{ fields: Object.fromEntries(Object.entries(context).map(([field, value]) => [field, { source: value }])) }} />
                {Object.keys((access.raw_source ?? {}) as Row).length ? <details><summary>Mapped raw source fields</summary><pre>{JSON.stringify(access.raw_source, null, 2)}</pre></details> : null}
              </article>
            );
          })}
        </section>
      ) : null}
      {(result.mapping as Row | undefined)?.warning ? <p className="form-notice">One or more mapped source fields were unavailable in this collected artifact.</p> : null}
      <details>
        <summary>Technical details</summary>
        <pre>{JSON.stringify(result, null, 2)}</pre>
      </details>
    </div>
  );
}
/** Turns an ISO timestamp into something a person reads, without a date library. */
const when = (value: unknown): string => {
  const text = s(value, "");
  if (!text) return "—";
  const date = new Date(text);
  if (Number.isNaN(date.getTime())) return text;
  return date.toLocaleString(undefined, {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
};
function Home() {
  const q = useQuery({ queryKey: ["dashboard"], queryFn: () => getJson("dashboard") }),
    m = (q.data?.metrics ?? {}) as Row,
    attention = arr(q.data?.attention),
    campaigns = arr(q.data?.campaigns),
    sources = arr(q.data?.sources),
    expected = (q.data?.expected_state ?? null) as Row | null,
    mine = (q.data?.mine ?? {}) as Row,
    myReviews = (mine.reviews ?? {}) as Row,
    myRights = arr(mine.owned_accesses),
    myReviewsDone = Number(myReviews.total ?? 0) - Number(myReviews.pending ?? 0),
    collectedFrom = vals(q.data?.collected_from).join(", "),
    tiles: [string, unknown, string, string][] = [
      ["Open campaigns", m.campaigns, "/campaigns", "in progress"],
      ["Reviews waiting", m.pending_reviews, "/reviews", "to be decided"],
      ["Findings", m.findings, "/findings", "in the last collection"],
      ["Remediation actions", m.remediation_actions, "/actions", "to carry out"],
    ];
  if (q.isLoading) return <div className="empty">{ui("common.loading")}</div>;
  if (q.isError)
    return (
      <div className="empty">
        {s(q.error)}{" "}
        <button className="button subtle" onClick={() => q.refetch()}>
          Retry
        </button>
      </div>
    );
  return (
    <>
      <Head title="Overview">
        <NavLink className="button primary" to="/campaigns/new">
          + New campaign
        </NavLink>
      </Head>
      <p className="muted">
        {q.data?.collected_at
          ? `Data collected ${when(q.data.collected_at)}${collectedFrom ? ` · ${collectedFrom}` : ""}`
          : "Nothing has been collected yet."}
        {expected
          ? ` · Expected state: ${s(expected.name)} v${s(expected.version)} (${s(expected.assignments, "0")} accesses)`
          : " · No expected state yet"}
      </p>
      <div className="metrics">
        {tiles.map(([label, value, link, hint]) => (
          <NavLink className="metric" to={link} key={label}>
            <div className="metric-label">{uiLabel(label)}</div>
            <strong>{s(value, "0")}</strong>
            <small>{uiLabel(hint)}</small>
          </NavLink>
        ))}
      </div>
      {Number(myReviews.total ?? 0) || myRights.length ? (
        <div className="dashboard-grid">
          <section className="panel">
            <div className="panel-title">
              <h2>{uiLabel("Your reviews")}</h2>
              <NavLink className="text-button" to="/reviews">
                {uiLabel("Open my queue")}
              </NavLink>
            </div>
            {Number(myReviews.total ?? 0) ? (
              <div className="progress-row" style={{ borderTop: 0, paddingTop: 0 }}>
                <div className="progress-head">
                  <span>
                    {myReviewsDone} of {s(myReviews.total, "0")} decided
                  </span>
                  <span>{Math.round((myReviewsDone / Math.max(1, Number(myReviews.total))) * 100)}%</span>
                </div>
                <div className="review-progress">
                  <div>
                    <span
                      style={{ width: `${(myReviewsDone / Math.max(1, Number(myReviews.total))) * 100}%` }}
                    />
                  </div>
                </div>
                <small>
                  {s(myReviews.pending, "0")} left
                  {vals(myReviews.campaigns).length
                    ? ` · ${vals(myReviews.campaigns).length} campaign(s)`
                    : ""}
                </small>
              </div>
            ) : (
              <p className="muted">{ui("dashboard.noReviewAssigned")}</p>
            )}
          </section>
          <section className="panel">
            <div className="panel-title">
            <h2>{ui("dashboard.accessRightsYouOwn")}</h2>
              <span className="muted">
                {s(mine.owned_total, "0")} right(s)
                {vals(mine.applications).length ? ` · ${vals(mine.applications).join(", ")}` : ""}
              </span>
            </div>
            {myRights.length ? (
              myRights.map((row) => (
                <div className="attention" key={`${s(row.provider)}-${s(row.access_name)}`}>
                  <div className="attention-icon blue">
                    <KeyRound size={17} />
                  </div>
                  <div>
                    <strong>{s(row.access_display_name, s(row.access_name))}</strong>
                    <p>
                      {s(row.application, s(row.provider))} · {s(row.holders, "0")} holder(s)
                      {s(row.description, "") ? ` · ${s(row.description)}` : ""}
                    </p>
                  </div>
                </div>
              ))
            ) : (
              <p className="muted">No access right lists you as its owner in the collected data.</p>
            )}
          </section>
        </div>
      ) : null}
      <div className="dashboard-grid">
        <section className="panel">
          <div className="panel-title">
            <h2>{uiLabel("Needs attention")}</h2>
            <span className="muted">
              {attention.length ? `${attention.length} item(s)` : "nothing pending"}
            </span>
          </div>
          {attention.length ? (
            attention.map((row, i) => (
              <NavLink className="attention" to={s(row.link, "/")} key={i}>
                <div className={`attention-icon ${s(row.tone, "blue")}`}>
                  {s(row.tone) === "red" ? (
                    <AlertTriangle size={17} />
                  ) : s(row.tone) === "amber" ? (
                    <AlertTriangle size={17} />
                  ) : (
                    <ChevronRight size={17} />
                  )}
                </div>
                <div>
                  <strong>{s(row.title)}</strong>
                  <p>{s(row.detail)}</p>
                </div>
                <ChevronRight size={16} />
              </NavLink>
            ))
          ) : (
            <p className="muted">
              {q.data?.collected_at
                ? "No collected issue or campaign needs attention right now."
                : <>No collection is available yet. <NavLink to="/sources">Configure and synchronize a source</NavLink> to start reviewing access.</>}
            </p>
          )}
        </section>
        <section className="panel">
          <div className="panel-title">
            <h2>{uiLabel("Campaigns in progress")}</h2>
            <NavLink className="text-button" to="/campaigns">
              {ui("nav.seeAll")}
            </NavLink>
          </div>
          {campaigns.length ? (
            campaigns.map((row) => {
              const total = Number(row.review_items) || 0,
                pending = Number(row.pending) || 0,
                done = total - pending;
              return (
                <div className="progress-row" key={s(row.id)}>
                  <div className="progress-head">
                    <NavLink to={`/campaigns/${s(row.id)}`}>{s(row.name)}</NavLink>
                    <span>{total ? Math.round((done / total) * 100) : 0}%</span>
                  </div>
                  <div className="review-progress">
                    <div>
                      <span style={{ width: `${total ? (done / total) * 100 : 0}%` }} />
                    </div>
                  </div>
                  <small>
                    {done} of {total} decided{row.due_at ? ` · due ${when(row.due_at)}` : ""}
                  </small>
                </div>
              );
            })
          ) : (
            <p className="muted">No campaign is open. Start one when a collection is up to date.</p>
          )}
          <div className="panel-title" style={{ marginTop: 24 }}>
            <h2>{ui("dashboard.sources")}</h2>
            <NavLink className="text-button" to="/sources">
              {ui("nav.manage")}
            </NavLink>
          </div>
          {sources.length ? (
            sources.map((row) => (
              <div className="attention" key={s(row.name)}>
                <div className={`attention-icon ${s(row.health) === "healthy" ? "blue" : "amber"}`}>
                  <Database size={17} />
                </div>
                <div>
                  <strong>{s(row.name)}</strong>
                  <p>
                    {s(row.health).replaceAll("_", " ")} ·{" "}
                    {row.last_sync ? when(row.last_sync) : "never collected"}
                    {Number(row.identity_count) ? ` · ${s(row.identity_count)} identities` : ""}
                  </p>
                </div>
              </div>
            ))
          ) : (
            <p className="muted">No source configured yet. <NavLink to="/sources">Configure a source</NavLink> to begin collection.</p>
          )}
        </section>
      </div>
    </>
  );
}
function useList(path: string, extra: Row = {}) {
  const [search, setSearch] = useState(""),
    [offset, setOffset] = useState(0),
    [limit, setLimit] = useState(25),
    [sort, setSort] = useState(""),
    [order, setOrder] = useState("asc"),
    [columnFilters, setColumnFilters] = useState<Row>({}),
    selected = debounce(search),
    appliedFilters = JSON.parse(debounce(JSON.stringify(columnFilters))) as Row;
  const q = useQuery({
    queryKey: [path, selected, limit, offset, sort, order, appliedFilters, extra],
    queryFn: () =>
      getPage(path, {
        ...extra,
        search: selected,
        limit,
        offset,
        sort,
        order,
        ...Object.fromEntries(
          Object.entries(appliedFilters)
            .filter(([, value]) => s(value, ""))
            .map(([field, value]) => [`f.${field}`, String(value)]),
        ),
      }),
  });
  // Any change of what is being listed sends the reader back to the first page.
  useEffect(
    () => setOffset(0),
    [selected, sort, order, JSON.stringify(appliedFilters), JSON.stringify(extra)],
  );
  const sorting: SortState = {
    sort,
    order,
    toggle: (field: string) => {
      setOrder(sort === field && order === "asc" ? "desc" : "asc");
      setSort(field);
    },
  };
  const filtering: FilterState = {
    values: columnFilters,
    set: (field, value) => setColumnFilters((all) => ({ ...all, [field]: value })),
  };
  return { q, search, setSearch, offset, setOffset, limit, setLimit, sorting, filtering };
}
function Identities() {
  const [provider, setProvider] = useState(""),
    [status, setStatus] = useState(""),
    x = useList("identities", { provider, status }),
    [selected, setSelected] = useState<Row | null>(null);
  return (
    <>
      <Head title="Identities" />
      <Filter v={x.search} onChange={x.setSearch}>
        <ProviderFilter
          value={provider}
          onChange={setProvider}
          placeholder="Source / IdP"
        />
        <SelectFilter
          value={status}
          onChange={setStatus}
          options={["active", "disabled", "group", "user"]}
          placeholder="Status / type"
        />
      </Filter>
      <Table
        cols={["Identity", "Type", "Source / IdP", "Status", "Accesses", "Findings"]}
        fields={["display_name", "type", "provider", "status", "access_count", "finding_count"]}
        sorting={x.sorting}
        filtering={x.filtering}
        q={x.q}
        onRow={(i) => setSelected((x.q.data?.items ?? [])[i])}
        emptyTitle="No identities found"
        emptyText="No identity matches the current source, status and search filters."
        rows={(x.q.data?.items ?? []).map((r) => [
          <>
            <button className="link-button" onClick={() => setSelected(r)}>
              {s(r.display_name, s(r.identifier))}
            </button>
            <Sub>{[s(r.description, ""), s(r.email, "")].filter(Boolean).join(" · ")}</Sub>
          </>,
          s(r.type).replaceAll("_", " "),
          s(r.provider),
          <Status v={r.status} />,
          s(r.access_count, "0"),
          s(r.finding_count, "0"),
        ])}
      />
      <Pager
        total={x.q.data?.total ?? 0}
        limit={x.limit}
        offset={x.offset}
        setOffset={x.setOffset}
        setLimit={x.setLimit}
      />
      {selected && <IdentityDrawer identity={selected} close={() => setSelected(null)} />}
    </>
  );
}
function IdentityDrawer({ identity, close }: { identity: Row; close: () => void }) {
  const q = useQuery({
      queryKey: ["identity-accesses", identity.id],
      queryFn: () =>
        getJson(`identities/${encodeURIComponent(s(identity.id, s(identity.identifier)))}/accesses`),
    }),
    [access, setAccess] = useState<Row | null>(null),
    rows: Row[] = [
      ...arr(q.data?.accesses).map((r) => ({ ...r, mode: "Direct" })),
      ...arr(q.data?.effective_accesses).map((r) => ({ ...r, mode: "Effective" })),
    ];
  return (
    <Drawer title={s(identity.display_name, s(identity.identifier))} close={close} size="wide">
      {access ? (
        <>
          <button className="drawer-back" onClick={() => setAccess(null)}>
            <ArrowLeft size={15} /> {s(identity.display_name, s(identity.identifier))}
          </button>
          <div className="drawer-breadcrumb">
            <span>{s(identity.display_name, s(identity.identifier))}</span>
            <ChevronRight size={14} />
            <strong>{s(access.display_name, s(access.name))}</strong>
          </div>
          <AccessDetail access={access} />
        </>
      ) : (
        <>
          <h4>PROFILE</h4>
          <p>{describeIdentity(identity) || "No description provided by the source."}</p>
          <p>
            {s(identity.type).replaceAll("_", " ")} · {s(identity.provider)} · <Status v={identity.status} />
          </p>
          {identity.account_owner ? (
            <p>Account owner: {s((identity.account_owner as Row | undefined)?.identity)}</p>
          ) : null}
          <h4>ACCESSES</h4>
          <Table
            cols={["Access", "Source", "Permission", "Mode"]}
            q={q}
            rows={rows.map((r) => [
              <>
                <button
                  className="link-button"
                  onClick={() =>
                    setAccess({
                      provider: r.access_provider ?? r.provider,
                      name: r.access_name,
                      display_name: r.access_display_name,
                      permission: r.permission,
                      target: r.target,
                      description: r.description,
                    })
                  }
                >
                  {s(r.access_display_name, s(r.access_name))}
                </button>
                <Sub>{describeAccess(r)}</Sub>
              </>,
              s(r.access_provider ?? r.provider),
              permissionText(r.permission) || "—",
              s(r.mode),
            ])}
          />
        </>
      )}
    </Drawer>
  );
}
function Accesses() {
  const [provider, setProvider] = useState(""),
    x = useList("accesses", { provider }),
    [selected, setSelected] = useState<Row | null>(null);
  return (
    <>
      <Head title="Access" />
      <Filter v={x.search} onChange={x.setSearch}>
        <ProviderFilter
          value={provider}
          onChange={setProvider}
          placeholder="Source / application"
        />
      </Filter>
      <Table
        cols={[
          "Access",
          "What it allows",
          "Source / application",
          "Permission",
          "Target",
          "Holders",
          "Findings",
        ]}
        fields={["display_name", "description", "provider", "permission", "target", null, null]}
        sorting={x.sorting}
        filtering={x.filtering}
        q={x.q}
        onRow={(i) => setSelected((x.q.data?.items ?? [])[i])}
        rows={(x.q.data?.items ?? []).map((r) => [
          <button className="link-button" onClick={() => setSelected(r)}>
            {s(r.display_name, s(r.name))}
          </button>,
          <Sub>{describeAccess(r)}</Sub>,
          s(r.provider),
          permissionText(r.permission) || "—",
          targetText(r.target) || "—",
          s(r.holder_count, "0"),
          s(r.finding_count, "0"),
        ])}
      />
      <Pager
        total={x.q.data?.total ?? 0}
        limit={x.limit}
        offset={x.offset}
        setOffset={x.setOffset}
        setLimit={x.setLimit}
      />
      {selected && <AccessDrawer access={selected} close={() => setSelected(null)} />}
    </>
  );
}
function AccessDetail({ access }: { access: Row }) {
  const client = useQueryClient(),
    toast = useToast(),
    [tab, setTab] = useState("overview"),
    [editingContext, setEditingContext] = useState(false),
    [manual, setManual] = useState<Row>(() => {
      const values = ((access.business_context as Row | undefined)?.manual_context ?? {}) as Row;
      return Object.fromEntries(["application", "business_permission", "resource", "description", "owner"].map((field) => [field, s((values[field] as Row | undefined)?.value, "")]));
    }),
    provider = s(access.provider ?? access.access_provider),
    name = s(access.name ?? access.access_name),
    accessId = s(access.id ?? access.access_id, ""),
    q = useQuery({
      queryKey: ["holders", provider, name],
      queryFn: () => getJson(`accesses/${encodeURIComponent(provider)}/${encodeURIComponent(name)}/holders`),
    }),
    ownerIdentities = useQuery({
      queryKey: ["access-owner-identities", provider],
      queryFn: () => getPage("identities", { provider, limit: 500 }),
      retry: false,
    }),
    saveContext = useMutation({
      mutationFn: () => putJson(`accesses/${encodeURIComponent(accessId)}/enrichment`, manual),
      onSuccess: async () => {
        setEditingContext(false);
        toast("ok", "Access information saved");
        await client.invalidateQueries({ queryKey: ["accesses"] });
        await client.invalidateQueries({ queryKey: ["golden-accesses"] });
        await client.invalidateQueries({ queryKey: ["golden-assignments"] });
        await client.invalidateQueries({ queryKey: ["review-items"] });
      },
      onError: (error) => toast("error", s(error, "Unable to save access information")),
    });
  const direct = arr(q.data?.holders),
    effective = arr(q.data?.effective_holders),
    ownerReference = contextValue(access.business_context, "owner", "manual") || contextValue(access.business_context, "owner", "source") || refText(access.access_owner) || s((access.access_owner as Row | undefined)?.identity, ""),
    ownerDisplay = ownerReference ? ownerDisplayLabel(ownerReference, arr(ownerIdentities.data?.items), s((access.access_owner as Row | undefined)?.provider, provider)) : "—";
  return (
    <>
      <div className="tabs">
        <button className={tab === "overview" ? "text-button active" : "text-button"} onClick={() => setTab("overview")}>Overview</button>
        <button className={tab === "holders" ? "text-button active" : "text-button"} onClick={() => setTab("holders")}>Holders</button>
      </div>
      {tab === "overview" ? (
        <>
          <h4>WHAT THIS ACCESS ALLOWS</h4>
          <p>{describeAccess(access) || "The source provided no description for this access."}</p>
          <h4>TECHNICAL ENTITLEMENT</h4>
          <p>Source: {provider}</p>
          <p>Granted via: {s(access.technical_grant, permissionText(access.permission) === "member" ? "Group membership" : "Direct assignment")}</p>
          <p>Technical permission: {s(access.technical_permission, permissionText(access.permission) || "—")}</p>
          <p>Target: {targetText(access.target) || "—"}</p>
          <h4>BUSINESS CONTEXT</h4>
          <BusinessContext context={access.business_context} />
          {accessId ? <button className="button subtle" onClick={() => setEditingContext(!editingContext)}>Edit access information</button> : null}
          {editingContext ? (
            <div className="drawer-form">
              {[
                ["Application", "application"],
                ["Permission", "business_permission"],
                ["Resource", "resource"],
                ["Description", "description"],
                ["Owner", "owner"],
              ].map(([label, field]) => (
                <label key={field}>{label}<input value={s(manual[field], "")} onChange={(event) => setManual((current) => ({ ...current, [field]: event.target.value }))} /></label>
              ))}
              <button className="button primary" disabled={saveContext.isPending} onClick={() => saveContext.mutate()}>Save manual reference</button>
            </div>
          ) : null}
          <h4>DETAILS</h4>
          <p>
            Owner:{" "}
            {ownerDisplay}
          </p>
          <h4>WHO HOLDS IT</h4>
          <p>
            {direct.length} direct · {effective.length} effective
          </p>
        </>
      ) : (
        <Table
          cols={["Identity", "Direct / Effective", "Why"]}
          q={q}
          rows={[
            ...direct.map((r) => ({ ...r, mode: "Direct" })),
            ...effective.map((r) => ({ ...r, mode: "Effective" })),
          ].map((r: Row) => [
            <strong>{s(r.identity_display_name, s(r.identity_identifier))}</strong>,
            s(r.mode),
            <AccessPath
              direct={r.mode === "Direct"}
              identity={s(r.identity_display_name, s(r.identity_identifier))}
              paths={arr(r.paths)}
            />,
          ])}
        />
      )}
    </>
  );
}
function AccessDrawer({ access, close }: { access: Row; close: () => void }) {
  return (
    <Drawer title={s(access.display_name, s(access.name ?? access.access_name))} close={close} size="wide">
      <AccessDetail access={access} />
    </Drawer>
  );
}
/** Parts of a whole, as one bar. Every segment keeps its label and its count. */
function StackedBar({ parts }: { parts: { label: string; value: number; tone: string }[] }) {
  const total = parts.reduce((sum, part) => sum + part.value, 0);
  if (!total) return null;
  return (
    <div className="stacked">
      <div className="stacked-track">
        {parts
          .filter((part) => part.value > 0)
          .map((part) => (
            <span
              key={part.label}
              className={`stacked-part ${part.tone}`}
              style={{ width: `${(part.value / total) * 100}%` }}
              title={`${part.label}: ${part.value}`}
            />
          ))}
      </div>
      <div className="stacked-legend">
        {parts
          .filter((part) => part.value > 0)
          .map((part) => (
            <span key={part.label}>
              <span className={`stacked-dot ${part.tone}`} />
              {part.label}
              <strong>{part.value}</strong>
            </span>
          ))}
      </div>
    </div>
  );
}
/** Decide straight from the row. A revoke or an N/A still asks for its reason. */
function RowDecision({ item, done }: { item: Row; done?: () => void }) {
  const toast = useToast(),
    c = useQueryClient(),
    [asking, setAsking] = useState<string | null>(null),
    [reason, setReason] = useState(""),
    m = useMutation({
      mutationFn: (choice: { value: string; comment?: string }) =>
        postDecision(s(item.id), choice.value, choice.comment),
      onSuccess: async (_d, choice) => {
        setAsking(null);
        setReason("");
        toast(
          "ok",
          `${s(item.identity_display_name, s(item.identity_identifier))}: ${
            choice.value === "approve"
              ? "approved"
              : choice.value === "revoke"
                ? "revoked"
                : "marked not applicable"
          }`,
        );
        await c.invalidateQueries({ queryKey: ["review-items"] });
        done?.();
      },
      onError: (e) => toast("error", s(e, "The decision was refused")),
    });
  return (
    <>
      <div className="row-actions">
        <button className="decision-action approve" disabled={m.isPending} onClick={() => m.mutate({ value: "approve" })}>
          Approve
        </button>
        <button className="decision-action revoke" disabled={m.isPending} onClick={() => setAsking("revoke")}>
          Revoke
        </button>
        <button className="decision-action" disabled={m.isPending} onClick={() => setAsking("not_applicable")}>
          N/A
        </button>
      </div>
      {asking ? (
        <Confirm
          title={asking === "revoke" ? "Revoke this access?" : "Mark as not applicable?"}
          intro={
            <p>
              {s(item.identity_display_name, s(item.identity_identifier))} →{" "}
              {s(item.access_display_name, s(item.access_name))}
            </p>
          }
          confirmLabel={asking === "revoke" ? "Revoke" : "Mark not applicable"}
          danger={asking === "revoke"}
          pending={m.isPending}
          disabled={!reason.trim()}
          cancel={() => {
            setAsking(null);
            setReason("");
          }}
          confirm={() => m.mutate({ value: asking, comment: reason.trim() })}
        >
          <label>
            Reason
            <input
              autoFocus
              value={reason}
              placeholder="Why does this decision apply?"
              onChange={(e) => setReason(e.target.value)}
            />
          </label>
        </Confirm>
      ) : null}
    </>
  );
}
function Reviews() {
  const campaigns = useQuery({
      queryKey: ["review-campaigns"],
      queryFn: () => getPage("campaigns", { limit: 100 }),
    }),
    [decision, setDecision] = useState(""),
    [campaign, setCampaign] = useState(""),
    [classification, setClassification] = useState(""),
    x = useList("review-items", { status: decision, campaign, classification }),
    [selected, setSelected] = useState<Row | null>(null),
    summary = (x.q.data?.summary ?? null) as Row | null,
    states = ((summary?.classification ?? {}) as Row) || {},
    decisions = ((summary?.decision ?? {}) as Row) || {},
    completion = Math.round((Number(summary?.decided) / Math.max(1, Number(summary?.total))) * 100);
  return (
    <>
      <Head title="My Reviews" subtitle="Review and certify the access rights assigned to you." />
      {summary ? (
        <section className="review-summary">
          <div className="review-summary-main">
            <div className="review-kpis">
              <div className="review-kpi pending"><strong>{s(summary.pending, "0")}</strong><span>Pending</span></div>
              <div className="review-kpi"><strong>{s(decisions.approve, "0")}</strong><span>Approved</span></div>
              <div className="review-kpi"><strong>{s(decisions.revoke, "0")}</strong><span>Revoked</span></div>
              <div className="review-kpi"><strong>{s(decisions.not_applicable, "0")}</strong><span>Not applicable</span></div>
            </div>
            <div className="progress-head"><strong>{completion}% complete</strong><span>{s(summary.decided, "0")} / {s(summary.total, "0")} decided</span></div>
            <div className="review-progress">
              <div>
                <span style={{ width: `${completion}%` }} />
              </div>
            </div>
          </div>
          <StackedBar
            parts={[
              { label: "As expected", value: Number(states.expected_and_observed) || 0, tone: "ok" },
              { label: "No reference", value: Number(states.no_reference) || 0, tone: "neutral" },
              { label: "Missing", value: Number(states.missing) || 0, tone: "warn" },
              { label: "Not expected", value: Number(states.unexpected) || 0, tone: "bad" },
            ]}
          />
          <span className="review-findings">
            {s(summary.with_findings, "0")} with findings
          </span>
        </section>
      ) : null}
      <Filter v={x.search} onChange={x.setSearch}>
        <SelectFilter
          value={classification}
          onChange={setClassification}
          options={Object.keys(states)}
          placeholder="State"
        />
        <CampaignFilter
          value={campaign}
          onChange={setCampaign}
          campaigns={arr(campaigns.data?.items)}
        />
        <SelectFilter
          value={decision}
          onChange={setDecision}
          options={["pending", "approve", "revoke", "not_applicable"]}
          placeholder="Decision"
        />
      </Filter>
      <Table
        cols={["Identity", "Access", "Application", "Classification", "Latest decision", "Decide"]}
        emptyTitle="No reviews assigned"
        emptyText="There is currently nothing waiting for your decision in this view."
        fields={[
          "identity_display_name",
          "access_display_name",
          "target",
          "classification",
          "decision",
          null,
        ]}
        sorting={x.sorting}
        filtering={x.filtering}
        q={x.q}
        rows={[...(x.q.data?.items ?? [])]
          .sort(pendingFirst)
          .map((r) => [
            <>
              <button className="link-button cell-primary" onClick={() => setSelected(r)}>
                {s(r.identity_display_name, s(r.identity_identifier))}
              </button>
              <Sub>{s(r.identity_identifier)} · {s(r.identity_provider)}</Sub>
            </>,
            <><strong>{s(r.access_display_name, s(r.access_name))}</strong><Sub>{describeAccess(r)}</Sub></>,
            <><span>{contextValue(r.business_context, "application", "manual") || contextValue(r.business_context, "application", "source") || "Unknown"}</span><Sub>{contextValue(r.business_context, "business_permission", "manual") || contextValue(r.business_context, "business_permission", "source") || "Not provided"}</Sub></>,
            <Status v={r.classification} />,
            <Status v={r.decision ?? "pending"} />,
            <RowDecision item={r} />,
          ])}
      />
      <Pager
        total={x.q.data?.total ?? 0}
        limit={x.limit}
        offset={x.offset}
        setOffset={x.setOffset}
        setLimit={x.setLimit}
      />
      {selected && (
        <ReviewDrawer
          item={selected}
          items={x.q.data?.items ?? []}
          close={() => setSelected(null)}
          next={setSelected}
        />
      )}
    </>
  );
}
function ReviewDrawer({
  item,
  items,
  close,
  next,
}: {
  item: Row;
  items: Row[];
  close: () => void;
  next: (x: Row | null) => void;
}) {
  const c = useQueryClient(),
    toast = useToast(),
    [reason, setReason] = useState(""),
    [pending, setPending] = useState<string | null>(null);
  const m = useMutation({
    mutationFn: (v: string) => postDecision(s(item.id), v, reason.trim() || undefined),
    onSuccess: async () => {
      toast("ok", `${who}: decision recorded`);
      await c.invalidateQueries({ queryKey: ["review-items"] });
      const i = items.findIndex((r) => r.id === item.id);
      next(items.slice(i + 1).find((r) => !r.decision) || null);
      setPending(null);
      setReason("");
    },
    onError: (e) => toast("error", s(e, "The decision was refused")),
  });
  const paths = arr(item.paths),
    who = s(item.identity_display_name, s(item.identity_identifier)),
    what = s(item.access_display_name, s(item.access_name)),
    latest = (item.latest_decision ?? null) as Row | null;
  return (
    <Drawer title={who} close={close}>
      <section className="drawer-section">
        <h4>WHO</h4>
        <strong className="drawer-primary">{who}</strong>
        <p>{s((item.identity as Row | undefined)?.email, s(item.identity_identifier))}</p>
        <p className="muted">{s(item.identity_provider)}</p>
      </section>
      <section className="drawer-section">
        <h4>WHAT ACCESS</h4>
        <strong className="drawer-primary">{what}</strong>
        <p>{describeAccess(item) || "The source provided no description for this access."}</p>
        <p>Source: {s(item.access_provider)}</p>
        <p>Granted via: {s(item.technical_grant, "Direct assignment")} · Technical permission: {s(item.technical_permission, "—")}</p>
      </section>
      <section className="drawer-section">
        <h4>BUSINESS CONTEXT</h4>
        <BusinessContext context={item.business_context} manualStatus={s(item.manual_context_capture_status)} />
      </section>
      {item.golden_comment ? (
        <section className="drawer-section">
          <h4>GOLDEN COMMENT</h4>
          <p>{s(item.golden_comment)}</p>
        </section>
      ) : null}
      <section className="drawer-section">
        <h4>CURRENT STATE</h4>
        <div className="state-grid">
          <div><span>Expected</span><strong>{item.expected ? "Yes" : "No"}</strong></div>
          <div><span>Observed</span><strong>{item.observed ? "Yes" : "No"}</strong></div>
        </div>
      </section>
      <section className="drawer-section">
        <h4>CLASSIFICATION</h4>
        <Status v={item.classification} />
      </section>
      <section className="drawer-section">
      <h4>WHY</h4>
        <AccessPath direct={Boolean(item.direct)} identity={who} paths={paths} />
      </section>
      {vals(item.findings).length ? <section className="drawer-section"><h4>FINDINGS</h4><div className="badge-list">{vals(item.findings).map((finding) => <Status key={finding} v={finding} />)}</div></section> : null}
      {latest ? (
        <section className="decision-record">
          <h4>EXISTING DECISION</h4>
          <Status v={latest.value} />
          {latest.comment ? <p>{s(latest.comment)}</p> : null}
          <small>{s(latest.decided_by, "Unknown reviewer")} · {when(latest.created_at)}</small>
        </section>
      ) : null}
      {pending && (
        <div className="reason-form">
          <label>
            Review comment {pending === "approve" ? "(optional)" : "*"}<textarea autoFocus value={reason} onChange={(e) => setReason(e.target.value)} />
          </label>
          <button
            onClick={() => {
              setPending(null);
              setReason("");
            }}
          >
            Cancel
          </button>
          <button disabled={(pending !== "approve" && !reason.trim()) || m.isPending} onClick={() => m.mutate(pending)}>
            Confirm {pending === "revoke" ? "revoke" : pending === "approve" ? "approve" : "N/A"}
          </button>
        </div>
      )}
      {!pending && (
        <div className="drawer-footer">
          <button onClick={() => setPending("not_applicable")}>N/A</button>
          <button onClick={() => setPending("revoke")}>Revoke</button>
          <button className="button primary" onClick={() => setPending("approve")}>
            Approve
          </button>
        </div>
      )}
    </Drawer>
  );
}
function List({ path, title }: { path: string; title: string }) {
  const campaigns = useQuery({
      queryKey: [path, "campaigns"],
      queryFn: () => getPage("campaigns", { limit: 100 }),
    }),
    findings = path === "findings",
    [provider, setProvider] = useState(""),
    [status, setStatus] = useState(""),
    [action, setAction] = useState(""),
    [campaign, setCampaign] = useState(""),
    x = useList(path, { provider, status, campaign, action: path === "remediation-actions" ? action : undefined }),
    [selected, setSelected] = useState<Row | null>(null),
    campaignRows = arr(campaigns.data?.items),
    selectedCampaignName = s(
      campaignRows.find((item) => s(item.id) === campaign)?.display_name,
      s(campaignRows.find((item) => s(item.id) === campaign)?.name, "Current state"),
    ),
    exportParams = new URLSearchParams({ provider, status, action, campaign });
  return (
    <>
      <Head title={title} />
      <Filter v={x.search} onChange={x.setSearch}>
        <ProviderFilter
          value={provider}
          onChange={setProvider}
          placeholder="Source"
        />
        <SelectFilter
          value={status}
          onChange={setStatus}
          options={findings ? ["unexpected", "missing", "expected_and_observed"] : ["pending", "exported", "completed", "not_completed"]}
          placeholder="Status"
        />
        {!findings ? (
          <SelectFilter value={action} onChange={setAction} options={["revoke", "grant"]} placeholder="Action" />
        ) : null}
        <CampaignFilter
          value={campaign}
          onChange={setCampaign}
          campaigns={campaignRows}
        />
      </Filter>
      <Table
          cols={
            findings
            ? ["Identity", "Access", "Source", "Classification", "Campaign", "Observed", "Expected"]
            : ["Identity", "Requested action", "Access / Application", "Campaign", "Reason", "Decision by", "Status"]
          }
          fields={
            findings
            ? ["identity_identifier", "access_name", "access_provider", "classification", null, null, null]
            : ["identity_display_name", "action", "access_display_name", "campaign_id", "comment", "decided_by", "status"]
          }
        sorting={x.sorting}
        filtering={x.filtering}
        q={x.q}
        rows={(x.q.data?.items ?? []).map((r) =>
          findings
            ? [
                <button
                  className="link-button"
                  onClick={() => setSelected({ ...r, campaign_id: campaign || null, campaign_name: selectedCampaignName })}
                >
                  {s((r.identity as Row | undefined)?.display_name, s(r.identity_identifier))}
                </button>,
                s((r.access as Row | undefined)?.display_name, s(r.access_name)),
                s(r.access_provider),
                <Status v={r.classification} />,
                selectedCampaignName,
                observedMeaning(r),
                expectedMeaning(r),
              ]
            : [
                <button className="link-button" onClick={() => setSelected(r)}>
                  {s(r.identity_display_name, s(r.identity_identifier))}
                </button>,
                s(r.action, s(r.decision)),
                s(r.access_display_name, s(r.access_name)),
                s(r.campaign_name, s(r.campaign_id)),
                s(r.comment),
                s(r.decided_by),
                <Status v={r.status} />,
              ],
        )}
      />
      {!findings ? <div className="button-row action-export-row"><a className="button subtle" href={`/api/remediation-actions/export?${exportParams.toString()}`}>Download remediation CSV</a></div> : null}
      <Pager
        total={x.q.data?.total ?? 0}
        limit={x.limit}
        offset={x.offset}
        setOffset={x.setOffset}
        setLimit={x.setLimit}
      />
      {selected &&
        (findings ? (
          <FindingDrawer row={selected} close={() => setSelected(null)} />
        ) : (
          <ActionDrawer row={selected} close={() => setSelected(null)} />
        ))}
    </>
  );
}
function FindingDrawer({ row, close }: { row: Row; close: () => void }) {
  const toast = useToast(),
    [ticket, setTicket] = useState(s((row.finding_tracking as Row | undefined)?.ticket, "")),
    [comment, setComment] = useState(s((row.finding_tracking as Row | undefined)?.comment, "")),
    save = useMutation({
      mutationFn: () => patchJson("findings/tracking", {
        campaign_id: row.campaign_id,
        access_provider: row.access_provider,
        access_name: row.access_name,
        identity_provider: row.identity_provider,
        identity_identifier: row.identity_identifier,
        classification: row.classification,
        ticket,
        comment,
      }),
      onSuccess: () => toast("ok", "Finding tracking saved"),
      onError: (error) => toast("error", s(error, "Unable to save finding tracking")),
    });
  return (
    <Drawer title="Finding" close={close}>
      <h4>WHAT HAPPENED</h4>
      <p>{s(vals(row.findings).join(", "), s(row.classification, "No classification"))}</p>
      <h4>CURRENT STATE</h4>
      <p>Observed: {readableDetails(row.observed)} · Expected: {readableDetails(row.expected)}</p>
      <h4>CONTEXT</h4>
      <p>Identity: {s((row.identity as Row | undefined)?.display_name, s(row.identity_identifier))}</p>
      <p>Access: {s((row.access as Row | undefined)?.display_name, s(row.access_name))}</p>
      <p className="muted">{describeAccess((row.access as Row) ?? row)}</p>
      <p>Source: {s(row.access_provider)}</p>
      {row.campaign_id != null || row.campaign_name ? <p>Campaign: {s(row.campaign_name, s(row.campaign_id))}</p> : null}
      <h4>OPTIONAL TICKET</h4>
      <label>Ticket reference<input value={ticket} onChange={(event) => setTicket(event.target.value)} placeholder="INC-1234 or Jira key" /></label>
      <label>Follow-up comment<textarea value={comment} onChange={(event) => setComment(event.target.value)} placeholder="Business or operational follow-up" /></label>
      <button className="button primary" disabled={save.isPending} onClick={() => save.mutate()}>Save ticket and comment</button>
    </Drawer>
  );
}
function ActionDrawer({ row, close }: { row: Row; close: () => void }) {
  const queryClient = useQueryClient(),
    toast = useToast(),
    [comment, setComment] = useState(""),
    update = useMutation({
      mutationFn: (status: string) => patchJson(`remediation-actions/${encodeURIComponent(s(row.id))}/status`, { status, comment }),
      onSuccess: async () => {
        toast("ok", "Remediation status saved");
        await queryClient.invalidateQueries({ queryKey: ["remediation-actions"] });
        close();
      },
      onError: (error) => toast("error", s(error, "Unable to update remediation status")),
    });
  return (
    <Drawer title={`${s(row.action, s(row.decision))} · ${s(row.access_display_name, s(row.access_name))}`} close={close}>
      <h4>WHAT TO DO</h4>
      <p>Identity: {s(row.identity_display_name, s(row.identity_identifier))}</p>
      <p>Access: {s(row.access_display_name, s(row.access_name))}</p>
      <p>{describeAccess(row) || "No description provided by the source."}</p>
      <p>Application / target: {targetText(row.target) || s(row.access_display_name, s(row.access_name))}</p>
      <h4>WHY</h4>
      <p>Campaign: {s(row.campaign_name, s(row.campaign_id))}</p>
      <p>Decision: {s(row.decision)}</p>
      <p>Comment: {s(row.comment)}</p>
      <h4>STATUS</h4>
      <Status v={row.status} />
      {s((row.details as Row | undefined)?.status_comment, "") ? <p className="muted">{s((row.details as Row | undefined)?.status_comment)}</p> : null}
      <label>
        Administrator comment
        <textarea value={comment} onChange={(event) => setComment(event.target.value)} placeholder="What was done, or why is it not completed?" />
      </label>
      <div className="button-row">
        <button className="button subtle" disabled={update.isPending} onClick={() => update.mutate("not_completed")}>Acknowledge / not completed</button>
        <button className="button" disabled={update.isPending} onClick={() => update.mutate("completed")}>Acknowledge completed</button>
      </div>
    </Drawer>
  );
}
function RemediationManager() {
  return (
    <>
      <Head title="Remediation follow-up" />
      <div className="panel page-intro">
        <h3>Operational remediation queue</h3>
        <p className="muted">Administrators record what was done or not done. EARE only records the follow-up and never changes a source.</p>
      </div>
      <List path="remediation-actions" title="Actions to follow up" />
    </>
  );
}
function CampaignWorkflow({ status, pending }: { status: string; pending: number }) {
  const steps = [
    ["Prepare", status === "draft" ? "active" : "done"],
    ["Review", status === "open" ? "active" : status === "draft" ? "pending" : "done"],
    ["Closed", status === "closed" ? "done" : "pending"],
    ["Remediation", status === "closed" ? (pending ? "active" : "done") : "pending"],
    ["Report", status === "closed" ? "active" : "pending"],
  ];
  return (
    <section className="panel campaign-workflow" aria-label="Campaign workflow">
      <div className="workflow-steps">
        {steps.map(([label, state], index) => (
          <div className={`workflow-step ${state}`} key={label}>
            <span>{state === "done" ? "✓" : index + 1}</span>
            <strong>{uiLabel(label)}</strong>
            {label === "Review" && status === "open" ? <small>{pending} pending</small> : null}
          </div>
        ))}
      </div>
      <p className="muted workflow-note">
        {status === "draft" ? "Prepare the scope, observed state, expected state and reviewers before opening." : null}
        {status === "open" ? "Reviewers certify access rights. Close the campaign when every review is decided." : null}
        {status === "closed" ? "The result is frozen. Remediation actions and the final report are now available." : null}
      </p>
    </section>
  );
}
function Campaigns() {
  const x = useList("campaigns");
  return (
    <>
      <Head title="Campaigns">
        <a className="button primary" href="/campaigns/new">
          + New campaign
        </a>
      </Head>
      <Filter v={x.search} onChange={x.setSearch} />
      <Table
        cols={["Campaign", "Scope", "Status", "Progress", "Pending", "Due date"]}
        fields={["name", null, "status", "progress", "pending", "due_at"]}
        sorting={x.sorting}
        filtering={x.filtering}
        q={x.q}
        rows={(x.q.data?.items ?? []).map((r) => [
          <NavLink to={"/campaigns/" + s(r.id)}>{s(r.name)}</NavLink>,
          s((r.scope as Row | undefined)?.type, "all"),
          <Status v={r.status} />,
          <div className="table-progress">
            <div>
              <span style={{ width: `${pct(r.progress)}%` }} />
            </div>
            {pct(r.progress)}%
          </div>,
          s(r.pending, "0"),
          when(r.due_at),
        ])}
      />
      <Pager
        total={x.q.data?.total ?? 0}
        limit={x.limit}
        offset={x.offset}
        setOffset={x.setOffset}
        setLimit={x.setLimit}
      />
    </>
  );
}
function CampaignNew({ principal }: { principal: Principal }) {
  const { id: draftId } = useParams(),
    campaignQuery = useQuery({ queryKey: ["campaign-edit", draftId], queryFn: () => getJson("campaigns/" + s(draftId)), enabled: Boolean(draftId) }),
    snap = useQuery({ queryKey: ["snapshots"], queryFn: () => getPage("snapshots", { limit: 100 }) }),
    pilotQuery = useQuery({ queryKey: ["campaign-pilots"], queryFn: () => getJson("campaign-pilots") }),
    gold = useQuery({
      queryKey: ["golden-versions"],
      queryFn: () => getPage("golden-source-versions", { limit: 100 }),
    }),
    providerQuery = useQuery({ queryKey: ["campaign-providers"], queryFn: () => getPage("providers", { limit: 500 }) }),
    [form, setForm] = useState<Row>({
      name: "",
      pilot: principal.username,
      snapshot_id: "",
      golden_source_version_id: "",
      due_at: "",
      scope_type: "all",
    }),
    accessQuery = useQuery({
      queryKey: ["campaign-scope-accesses", form.snapshot_id, form.golden_source_version_id],
      queryFn: () => getJson("campaign-scope-accesses", {
        snapshot_id: s(form.snapshot_id, ""),
        golden_source_version_id: s(form.golden_source_version_id, "") || undefined,
      }),
      enabled: Boolean(form.snapshot_id),
    }),
    [preview, setPreview] = useState<Row | null>(null),
    [allow, setAllow] = useState(false),
    previewM = useMutation({
      onError: (e: unknown) => toast("error", s(e, "Unable to preview the campaign")),
      mutationFn: () =>
        postJson("campaigns/preview", {
          ...form,
          scope: {
            type: s(form.scope_type, "all"),
            ...(form.scope_type === "providers" ? { values: vals(form.providers) } : {}),
            ...(form.scope_type === "accesses" ? { values: arr(form.accesses).map((access) => ({ provider: s(access.provider, ""), name: s(access.name, "") })) } : {}),
          },
        }),
      onSuccess: setPreview,
    }),
    toast = useToast(),
    create = useMutation({
      mutationFn: async (open: boolean) => {
        const { scope_type, providers, accesses, ...fields } = form;
        const payload = {
          ...fields,
          scope: {
            type: s(scope_type, "all"),
            ...(scope_type === "providers" ? { values: vals(providers) } : {}),
            ...(scope_type === "accesses" ? { values: arr(accesses).map((access) => ({ provider: s(access.provider, ""), name: s(access.name, "") })) } : {}),
          },
          allow_unresolved_reviewers: allow,
        };
        const d = draftId
          ? await putJson("campaigns/" + s(draftId), payload)
          : await postJson("campaigns", payload);
        if (open && !draftId && d.id)
          await postJson("campaigns/" + s(d.id) + "/open", { allow_unresolved_reviewers: allow });
        return d;
      },
      onSuccess: (d) => {
        toast("ok", draftId ? "Campaign draft updated" : "Campaign created");
        if (d.id) window.location.href = "/campaigns/" + s(d.id);
      },
      onError: (e) => toast("error", s(e, "Unable to create the campaign")),
    }),
    snapshots = arr(snap.data?.items),
    pilots = arr(pilotQuery.data?.items),
    versions = arr(gold.data?.items),
    providers = arr(providerQuery.data?.items),
    accessOptions = arr(accessQuery.data?.items),
    selectedAccesses = arr(form.accesses),
    scopeType = s(form.scope_type, "all"),
    campaignScopeValid = validProviderScope(scopeType, vals(form.providers)) && (scopeType !== "accesses" || selectedAccesses.length > 0);
  useEffect(() => {
    const campaign = campaignQuery.data?.campaign as Row | undefined;
    if (campaign && s(form.name, "") === "") {
      const scope = (campaign.scope ?? {}) as Row;
      const scopeType = s(scope.type, "all");
      setForm({
        name: s(campaign.name, ""),
        pilot: s(campaign.pilot, principal.username),
        snapshot_id: s(campaign.snapshot_id, ""),
        golden_source_version_id: s(campaign.golden_source_version_id, ""),
        due_at: s(campaign.due_at, ""),
        scope_type: scopeType,
        providers: vals(scope.values),
        accesses: arr(scope.values),
      });
    }
    if (!draftId && !form.snapshot_id && snapshots.length)
      setForm((x) => ({ ...x, snapshot_id: s(snapshots[snapshots.length - 1].id) }));
    if (!form.golden_source_version_id && versions.length)
      setForm((x) => ({ ...x, golden_source_version_id: s(versions[versions.length - 1].id) }));
  }, [snapshots.length, versions.length]);
  return (
    <>
      <Head title={draftId ? "Edit draft campaign" : "New campaign"}>
        <NavLink className="button subtle" to="/campaigns">
          Cancel
        </NavLink>
      </Head>
      <section className="panel campaign-form">
        <h2>Campaign setup</h2>
        <p className="muted">Define what will be compared and who will review it. Previewing does not persist anything.</p>
        <form
          className="admin-form"
          onSubmit={(e) => {
            e.preventDefault();
            previewM.mutate();
          }}
        >
          <h4 className="campaign-general">GENERAL</h4>
          <label>
            Name
            <input
              required
              value={s(form.name, "")}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
          </label>
          <label className="campaign-pilot">
            <span className="step-label">4</span> Campaign pilot / reviewers
            <select required value={s(form.pilot, principal.username)} onChange={(e) => setForm({ ...form, pilot: e.target.value })}>
              <option value="">Select an ADMIN or OPERATOR</option>
              {pilots.map((pilot) => <option key={s(pilot.username)} value={s(pilot.username)}>{s(pilot.display_name, s(pilot.username))} · {s(pilot.role)}</option>)}
            </select>
            <span className="field-note">The pilot manages the campaign. Group or role owners remain the reviewers.</span>
          </label>
          <label className="campaign-scope">
            <span className="step-label">1</span> Scope
            <select
              value={s(form.scope_type, "all")}
              onChange={(e) => setForm({ ...form, scope_type: e.target.value })}
            >
              <option value="all">All authorized sources</option>
              <option value="providers">Selected sources</option>
              <option value="accesses">Selected accesses</option>
            </select>
          </label>
          {form.scope_type === "providers" ? (
            <label className="wide-field campaign-scope">
              Providers
              <select
                multiple
                required
                size={Math.min(5, Math.max(2, providers.length))}
                value={vals(form.providers)}
                onChange={(event) =>
                  setForm({
                    ...form,
                    providers: Array.from(event.currentTarget.selectedOptions, (option) => option.value),
                  })
                }
              >
                {providers.map((provider) => (
                  <option key={s(provider.name)} value={s(provider.name)}>
                    {providerLabel(provider)}
                  </option>
                ))}
              </select>
              <span className="field-note">Choose at least one provider. Use Ctrl/Cmd to select several.</span>
            </label>
          ) : null}
          {form.scope_type === "accesses" ? (
            <label className="wide-field campaign-scope">
              Accesses
              <select
                multiple
                required
                size={Math.min(8, Math.max(3, accessOptions.length))}
                value={selectedAccesses.map((access) => JSON.stringify([s(access.provider, ""), s(access.name, "")]))}
                onChange={(event) => {
                  const selected = new Set(Array.from(event.currentTarget.selectedOptions, (option) => option.value));
                  setForm({
                    ...form,
                    accesses: accessOptions
                      .filter((access) => selected.has(JSON.stringify([s(access.provider, ""), s(access.name, "")])))
                      .map((access) => ({ provider: s(access.provider, ""), name: s(access.name, "") })),
                  });
                }}
              >
                {accessOptions.map((access) => (
                  <option key={JSON.stringify([access.provider, access.name])} value={JSON.stringify([access.provider, access.name])}>
                    {s(access.display_name, s(access.name))} · {s(access.name)} · {s(access.provider)}{access.application ? ` · ${s(access.application)}` : ""}
                  </option>
                ))}
              </select>
              <span className="field-note">The selected technical Access references (provider, name) determine which expected and observed comparisons are reviewed.</span>
            </label>
          ) : null}
          <label className="campaign-observed">
            <span className="step-label">2</span> Observed snapshot
            <select
              required
              value={s(form.snapshot_id, "")}
              onChange={(e) => setForm({ ...form, snapshot_id: e.target.value })}
            >
              <option value="">Select snapshot</option>
              {snapshots.map((r) => (
                <option key={s(r.id)} value={s(r.id)}>
                  {when(r.created_at)} · {s(r.assignment_count, "assignments unavailable")}
                </option>
              ))}
            </select>
          </label>
          <label className="campaign-expected">
            <span className="step-label">3</span> Expected state
            <select
              value={s(form.golden_source_version_id, "")}
              onChange={(e) => setForm({ ...form, golden_source_version_id: e.target.value || undefined })}
            >
              <option value="">None</option>
              {versions.map((r) => (
                <option key={s(r.id)} value={s(r.id)}>
                  v{s(r.version)} · {s(r.source_type, "Golden Source")}
                </option>
              ))}
            </select>
          </label>
          <label className="campaign-due">
            Due date
            <input
              type="date"
              value={s(form.due_at, "")}
              onChange={(e) => setForm({ ...form, due_at: e.target.value || undefined })}
            />
          </label>
          <div className="button-row wide-field campaign-submit">
            <button
              className="button subtle"
              type="button"
              disabled={!s(form.name, "") || !s(form.snapshot_id, "") || !campaignScopeValid || create.isPending}
              onClick={() => create.mutate(false)}
            >
              {draftId ? "Save draft changes" : "Save as draft"}
            </button>
            <button className="button primary" type="submit" disabled={!campaignScopeValid || previewM.isPending}>
              Preview campaign
            </button>
          </div>
        </form>
      </section>
      {preview && (
        <section className="panel">
          <h2><span className="step-label">5</span> Preview before opening</h2>
          <p className="muted">Preview calculates what would be reviewed. Open campaign freezes the Snapshot evidence, materializes ReviewItems and starts the review.</p>
          <div className="preview-context">
            <span><strong>Scope</strong>{scopeType === "providers" ? vals(form.providers).join(", ") : scopeType === "accesses" ? selectedAccesses.map((access) => `${s(access.provider)}/${s(access.name)}`).join(", ") : "All authorized sources"}</span>
            <span><strong>Snapshot</strong>{when(snapshots.find((row) => row.id === form.snapshot_id)?.created_at)}</span>
            <span><strong>Expected</strong>{versions.find((row) => row.id === form.golden_source_version_id) ? `Golden v${s(versions.find((row) => row.id === form.golden_source_version_id)?.version)}` : "No Golden version"}</span>
          </div>
          <div className="metrics">
            <div className="metric">
              <strong>{s(preview.total_review_items, "0")}</strong>
              <small>Review items</small>
            </div>
            <div className="metric">
              <strong>{s(preview.reviewer_count, "0")}</strong>
              <small>Reviewers</small>
            </div>
            <div className="metric">
              <strong>{s(preview.resolved_reviewers, "0")}</strong>
              <small>Resolved</small>
            </div>
            <div className="metric">
              <strong>{s(preview.unresolved_reviewers, "0")}</strong>
              <small>Unresolved</small>
            </div>
          </div>
          {Number(preview.unresolved_reviewers) > 0 && (
            <label>
              <input type="checkbox" checked={allow} onChange={(e) => setAllow(e.target.checked)} /> Allow
              unresolved reviewers
            </label>
          )}
          <div className="button-row">
            <button
              className="button subtle"
              disabled={create.isPending}
              onClick={() => create.mutate(false)}
            >
              Save as draft
            </button>
            <button
              className="button primary"
              disabled={!campaignScopeValid || (!allow && Number(preview.unresolved_reviewers) > 0) || create.isPending}
              onClick={() => create.mutate(true)}
            >
              Open campaign
            </button>
          </div>
        </section>
      )}
    </>
  );
}
function CampaignDetail() {
  const { id = "" } = useParams(),
    q = useQuery({ queryKey: ["campaign", id], queryFn: () => getJson("campaigns/" + id) }),
    c = q.data?.campaign as Row | undefined,
    [tab, setTab] = useState("overview"),
    [selected, setSelected] = useState<Row | null>(null),
    [selectedFinding, setSelectedFinding] = useState<Row | null>(null),
    [confirmAction, setConfirmAction] = useState<string | null>(null),
    toast = useToast(),
    m = useMutation({
      mutationFn: (a: string) => postJson("campaigns/" + id + "/" + a),
      onSuccess: (d, action) => {
        const actions = Number((d as Row)?.remediation_actions ?? 0);
        toast(
          "ok",
          action === "close"
            ? `Campaign closed · ${actions} remediation action(s) generated`
            : action === "promote"
              ? "Promoted to the Golden Source"
              : `Campaign ${action}ed`,
        );
        setConfirmAction(null);
        q.refetch();
      },
      onError: (e) => toast("error", s(e, "This operation was refused")),
    }),
    reviews = arr(q.data?.reviews),
    findings = arr(q.data?.findings),
    reviewerRows = Object.entries(
      reviews.reduce<Record<string, { total: number; decided: number }>>((acc, row) => {
        const name = s((row.reviewer as Row | undefined)?.identity, "unassigned"),
          entry = (acc[name] ??= { total: 0, decided: 0 });
        entry.total += 1;
        if (row.decision) entry.decided += 1;
        return acc;
      }, {}),
    )
      .map(([name, value]) => ({ name, ...value }))
      .sort((a, b) => b.total - b.decided - (a.total - a.decided)),
    findingRows = Object.entries(
      reviews.reduce<Record<string, number>>((acc, row) => {
        for (const finding of vals(row.findings)) acc[finding] = (acc[finding] ?? 0) + 1;
        return acc;
      }, {}),
    ).sort((a, b) => b[1] - a[1]),
    status = s(c?.status),
    pending = Number(c?.pending ?? reviews.filter((r) => !r.decision).length),
    ctas = campaignCtas(status, pending);
  if (!c) return <div className="empty">{q.isLoading ? "Loading..." : "Campaign not found"}</div>;
  return (
    <>
      <Head title={s(c.name)}>
        <div className="button-row">
          <NavLink to="/campaigns">Back</NavLink>
          {status === "draft" ? <NavLink className="button subtle" to={"/campaigns/" + id + "/edit"}>Edit draft</NavLink> : null}
          {ctas.map((action) => {
            const target = campaignActionTarget(action, id),
              labels: Record<string, string> = {
                open: "Open campaign",
                cancel: "Cancel campaign",
                close: "Close campaign",
                "close-disabled": "Close campaign",
                promote: "Promote to Golden",
                report: "Generate report",
              };
            return target ? (
              <NavLink className="button subtle" key={action} to={target}>{labels[action]}</NavLink>
            ) : (
              <button
                className={action === "open" ? "button primary" : "button subtle"}
                key={action}
                disabled={action === "close-disabled"}
                title={action === "close-disabled" ? `${pending} reviews still need a decision` : undefined}
                onClick={() => ["cancel", "close", "promote"].includes(action) ? setConfirmAction(action) : m.mutate(action)}
              >
                {labels[action]}
              </button>
            );
          })}
        </div>
      </Head>
      <CampaignWorkflow status={status} pending={pending} />
      <div className="tabs">
        <button
          className={tab === "overview" ? "text-button active" : "text-button"}
          onClick={() => setTab("overview")}
        >
          Overview
        </button>
        <button
          className={tab === "reviews" ? "text-button active" : "text-button"}
          onClick={() => setTab("reviews")}
        >
          Reviews
        </button>
        <button
          className={tab === "findings" ? "text-button active" : "text-button"}
          onClick={() => setTab("findings")}
        >
          Findings
        </button>
      </div>
      {tab === "overview" && (
        <>
          <div className="metrics">
            {[
              ["Reviews", Number(c.review_items ?? reviews.length), "in this campaign"],
              ["Decided", Number(c.review_items ?? reviews.length) - pending, "so far"],
              ["Still waiting", pending, "to be decided"],
              ["With findings", reviews.filter((r) => arr(r.findings).length).length, "need attention"],
            ].map(([label, value, hint]) => (
              <div className="metric" key={String(label)}>
                <div className="metric-label">{String(label)}</div>
                <strong>{s(value, "0")}</strong>
                <small>{String(hint)}</small>
              </div>
            ))}
          </div>
          {status === "closed" ? (
            <section className="panel campaign-result-panel">
              <div>
                <span className="eyebrow">Campaign result</span>
                <h2>Review completed</h2>
                <p className="muted">
                  {s(c.review_items ?? reviews.length, "0")} review items · {s(c.remediation_actions ?? (q.data?.remediation_summary as Row | undefined)?.total, "0")} remediation actions
                </p>
              </div>
              <div className="result-actions">
                <NavLink className="button primary" to={`/reports?campaign=${encodeURIComponent(id)}`}>View final report</NavLink>
                <a className="button subtle" href={`/api/reports/${encodeURIComponent(id)}/html`}>{uiLabel("Download HTML")}</a>
                <a className="button subtle" href={`/api/reports/${encodeURIComponent(id)}/pdf`}>{uiLabel("Download PDF")}</a>
                <a className="button subtle" href={`/api/reports/${encodeURIComponent(id)}/csv`}>{uiLabel("Download CSV")}</a>
                <a className="button subtle" href={`/api/reports/${encodeURIComponent(id)}/json`}>{uiLabel("Download JSON")}</a>
                <NavLink className="button subtle" to={`/actions?campaign=${encodeURIComponent(id)}`}>View remediation actions</NavLink>
                <button className="button subtle" type="button" onClick={() => setConfirmAction("promote")}>Promote decisions to Golden</button>
              </div>
            </section>
          ) : null}
          <div className="dashboard-grid">
            <section className="panel">
              <div className="panel-title">
                <h2>Where the campaign stands</h2>
                <span className="muted">
                  {pct(c.progress)}% decided
                  {c.due_at ? ` · due ${when(c.due_at)}` : ""}
                </span>
              </div>
              <StackedBar
                parts={[
                  { label: "Approved", value: count(reviews, (r) => r.decision === "approve"), tone: "ok" },
                  {
                    label: "Not applicable",
                    value: count(reviews, (r) => r.decision === "not_applicable"),
                    tone: "neutral",
                  },
                  { label: "Pending", value: pending, tone: "warn" },
                  { label: "Revoked", value: count(reviews, (r) => r.decision === "revoke"), tone: "bad" },
                ]}
              />
              <div className="panel-title" style={{ marginTop: 22 }}>
                <h2>What was compared</h2>
              </div>
              <StackedBar
                parts={[
                  {
                    label: "As expected",
                    value: count(reviews, (r) => r.classification === "expected_and_observed"),
                    tone: "ok",
                  },
                  {
                    label: "No reference",
                    value: count(reviews, (r) => r.classification === "no_reference"),
                    tone: "neutral",
                  },
                  {
                    label: "Missing",
                    value: count(reviews, (r) => r.classification === "missing"),
                    tone: "warn",
                  },
                  {
                    label: "Not expected",
                    value: count(reviews, (r) => r.classification === "unexpected"),
                    tone: "bad",
                  },
                ]}
              />
              <p className="muted" style={{ marginTop: 18 }}>
                {s((c.scope as Row | undefined)?.type, "all") === "providers"
                  ? `Providers: ${vals((c.scope as Row | undefined)?.values).join(", ")}`
                  : "All providers represented in the snapshot"}
              </p>
            </section>
            <section className="panel">
              <div className="panel-title">
                <h2>Who still has to decide</h2>
                <span className="muted">{reviewerRows.length} reviewer(s)</span>
              </div>
              {reviewerRows.length ? (
                reviewerRows.map((row) => (
                  <div className="progress-row" key={row.name}>
                    <div className="progress-head">
                      <span>{row.name}</span>
                      <span>
                        {row.decided}/{row.total}
                      </span>
                    </div>
                    <div className="review-progress">
                      <div>
                        <span style={{ width: `${(row.decided / Math.max(1, row.total)) * 100}%` }} />
                      </div>
                    </div>
                    <small>{row.total - row.decided} left</small>
                  </div>
                ))
              ) : (
                <p className="muted">No reviewer is assigned on this campaign.</p>
              )}
              {findingRows.length ? (
                <>
                  <div className="panel-title" style={{ marginTop: 24 }}>
                    <h2>Findings raised</h2>
                  </div>
                  {findingRows.map(([label, value]) => (
                    <div className="progress-row" key={label}>
                      <div className="progress-head">
                        <span>{label.replaceAll("_", " ")}</span>
                        <span>{value}</span>
                      </div>
                      <div className="review-progress">
                        <div>
                          <span style={{ width: `${(value / findingRows[0][1]) * 100}%` }} />
                        </div>
                      </div>
                    </div>
                  ))}
                </>
              ) : null}
            </section>
          </div>
        </>
      )}
      {tab === "reviews" && (
        <Table
          cols={["Identity", "Access", "Classification", "Decision", "Decide"]}
          rows={reviews.map((r) => [
            <button className="link-button" onClick={() => setSelected(r)}>
              {s(r.identity_display_name, s(r.identity_identifier))}
            </button>,
            s(r.access_display_name, s(r.access_name)),
            <Status v={r.classification} />,
            <Status v={r.decision ?? "pending"} />,
            <RowDecision item={r} done={() => q.refetch()} />,
          ])}
        />
      )}{" "}
      {tab === "findings" && (
        <Table
          cols={["Finding", "Campaign"]}
          rows={findings.map((f) => [
            <button
              className="link-button"
              onClick={() =>
                setSelectedFinding({ classification: "campaign finding", findings: [f], campaign_id: id })
              }
            >
              {s(f)}
            </button>,
            s(c.name),
          ])}
        />
      )}{" "}
      {selected && (
        <ReviewDrawer item={selected} items={reviews} close={() => setSelected(null)} next={setSelected} />
      )}{" "}
      {selectedFinding && <FindingDrawer row={selectedFinding} close={() => setSelectedFinding(null)} />}
      {confirmAction ? (
        <Confirm
          title={`${confirmAction === "promote" ? "Promote" : confirmAction === "close" ? "Close" : "Cancel"} ${s(c.name)}?`}
          intro={<p>{confirmAction === "promote" ? "This creates a new immutable Golden Source version from the campaign decisions." : confirmAction === "close" ? "The campaign will stop accepting decisions and remediation actions will be created." : "This draft campaign will be marked cancelled."}</p>}
          confirmLabel={confirmAction === "promote" ? "Promote to Golden" : confirmAction === "close" ? "Close campaign" : "Cancel campaign"}
          danger={confirmAction === "cancel"}
          pending={m.isPending}
          cancel={() => setConfirmAction(null)}
          confirm={() => m.mutate(confirmAction)}
        />
      ) : null}
    </>
  );
}
const goldenOrigin = (row: Row) => {
  const kind = s(row.source_type);
  if (kind === "promoted_campaign")
    return `Promoted from the campaign ${s(row.source_campaign_name, s(row.source_campaign_id, "—"))}`;
  if (kind === "promoted_observed_snapshot" || kind === "snapshot" || kind === "baseline")
    return `Adopted from what the systems contained on ${when(row.created_at)}`;
  if (kind === "csv") return "Imported from a CSV file";
  if (kind === "manual") return "Edited in the WebUI";
  if (kind === "from_scratch") return "Started empty";
  return s(kind, "Unknown origin");
};
const blankExpected = (): Row => ({
  access_provider: "",
  access_name: "",
  identity_provider: "",
  identity_identifier: "",
  access_permission: "",
});
/** Column filters for a screen that holds its own query, turned into f.<field> params. */
function useColumnFilters() {
  const [values, setValues] = useState<Row>({}),
    applied = JSON.parse(debounce(JSON.stringify(values))) as Row;
  return {
    filtering: {
      values,
      set: (field: string, value: string) => setValues((all) => ({ ...all, [field]: value })),
    } as FilterState,
    params: Object.fromEntries(
      Object.entries(applied)
        .filter(([, value]) => s(value, ""))
        .map(([field, value]) => [`f.${field}`, String(value)]),
    ),
    key: JSON.stringify(applied),
  };
}
function GoldenFunctionalSuggestions({ rows, onEdit }: { rows: Row[]; onEdit: (row: Row) => void }) {
  if (!rows.length) return <p className="muted">No observed Access business context is available for Golden suggestions.</p>;
  return (
    <div className="preview-accesses">
      {rows.map((row) => {
        const suggestions = (row.canonical_suggestions ?? {}) as Row;
        const target = (suggestions.target ?? {}) as Row;
        const service = (target.service ?? {}) as Row;
        const resource = (target.resource ?? {}) as Row;
        const owner = (suggestions.owner ?? {}) as Row;
        const mapped = vals(suggestions.mapped_capability_ids);
        return (
          <article key={`${s(row.access_provider)}:${s(row.access_name)}`}>
            <strong>{s(row.access_display_name, s(row.access_name))}</strong>
            <small>{s(row.access_provider)} · {row.business_context_conflicts ? "Conflict requires review" : "No context conflict"}</small>
            <BusinessContext context={{ fields: row.business_context_fields }} />
            <p className="muted">Canonical candidates (not expected truth):</p>
            <ul>
              {target.service ? <li>Target service: {refText(service)} · {s(service.provenance)}</li> : null}
              {target.resource ? <li>Target resource: {refText(resource)} · {s(resource.provenance)}</li> : null}
              {suggestions.description ? <li>Description: {s((suggestions.description as Row).value)} · {s((suggestions.description as Row).provenance)}</li> : null}
              {suggestions.owner ? <li>Owner candidate: {s(owner.identity)} · {s(owner.provenance)}{owner.known_identity ? " · known identity" : " · identity not resolved"}</li> : null}
              {mapped.length ? <li>Mapped capabilities: {mapped.join(", ")} · {s(suggestions.mapping_provenance, "mapped")}</li> : null}
              {suggestions.business_permission && !mapped.length ? <li>Business permission: {s((suggestions.business_permission as Row).value)} · unmapped</li> : null}
            </ul>
            <button className="button subtle" onClick={() => onEdit(row)}>Review and validate in Golden V2</button>
          </article>
        );
      })}
    </div>
  );
}
function Golden() {
  const c = useQueryClient(),
    q = useQuery({ queryKey: ["golden"], queryFn: () => getPage("golden-sources", { limit: 100 }) }),
    snap = useQuery({ queryKey: ["snap"], queryFn: () => getPage("snapshots", { limit: 100 }) }),
    goldens = arr(q.data?.items),
    [chosen, setChosen] = useState(""),
    source = goldens.find((row) => s(row.name) === chosen) ?? goldens[0],
    sourceName = s(source?.name, ""),
    encoded = encodeURIComponent(sourceName),
    [compare, setCompare] = useState<Row | null>(null),
    [notice, setNotice] = useState<{ tone: string; text: string } | null>(null),
    [name, setName] = useState("Main baseline"),
    [globalComment, setGlobalComment] = useState(""),
    [sid, setSid] = useState(""),
    [createMode, setCreateMode] = useState("snapshot"),
    [tab, setTab] = useState("accesses"),
    [holders, setHolders] = useState<Row | null>(null),
    [editingHolder, setEditingHolder] = useState<Row | null>(null),
    [editingAccess, setEditingAccess] = useState<Row | null>(null),
    [newApplication, setNewApplication] = useState<Row | null>(null),
    [functionalEditing, setFunctionalEditing] = useState<Row | null>(null),
    [adding, setAdding] = useState<Row | null>(null),
    [removing, setRemoving] = useState<Row | null>(null),
    providerOptions = useQuery({
      queryKey: ["golden-assignment-providers"],
      queryFn: () => getPage("providers", { limit: 500 }),
      retry: false,
    }),
    identityOptions = useQuery({
      queryKey: ["golden-assignment-identities", adding?.identity_provider],
      queryFn: () => getPage("identities", { provider: s(adding?.identity_provider), limit: 500 }),
      enabled: Boolean(adding?.identity_provider),
      retry: false,
    }),
    accessOptions = useQuery({
      queryKey: ["golden-assignment-accesses", adding?.access_provider],
      queryFn: () => getPage("accesses", { provider: s(adding?.access_provider), limit: 500 }),
      enabled: Boolean(adding?.access_provider),
      retry: false,
    }),
    holderIdentityOptions = useQuery({
      queryKey: ["golden-holder-identities", editingHolder?.identity_provider],
      queryFn: () => getPage("identities", { provider: s(editingHolder?.identity_provider), limit: 500 }),
      enabled: Boolean(editingHolder?.identity_provider),
      retry: false,
    }),
    ownerOptions = useQuery({
      queryKey: ["golden-access-owners"],
      queryFn: () => getPage("identities", { limit: 500 }),
      retry: false,
    }),
    applicationCatalog = useQuery({
      queryKey: ["golden-applications"],
      queryFn: () => getJson("golden-applications"),
      retry: false,
    }),
    [commenting, setCommenting] = useState<Row | null>(null),
    [assignmentComment, setAssignmentComment] = useState(""),
    [accessCommenting, setAccessCommenting] = useState<Row | null>(null),
    [accessComment, setAccessComment] = useState(""),
    [editingVersionComment, setEditingVersionComment] = useState(false),
    [versionComment, setVersionComment] = useState(""),
    [search, setSearch] = useState(""),
    selected = debounce(search),
    [offset, setOffset] = useState(0),
    [limit, setLimit] = useState(25),
    [sort, setSort] = useState(""),
    [order, setOrder] = useState("asc"),
    columns = useColumnFilters(),
    sorting: SortState = {
      sort,
      order,
      toggle: (field: string) => {
        setOrder(sort === field && order === "asc" ? "desc" : "asc");
        setSort(field);
        setOffset(0);
      },
    },
    accessesQuery = useQuery({
      queryKey: ["golden-accesses", sourceName, selected, limit, offset, sort, order, columns.key],
      queryFn: () =>
        getJson(`golden-sources/${encoded}/accesses`, {
          search: selected,
          limit,
          offset,
          sort,
          order,
          ...columns.params,
        }),
      enabled: Boolean(sourceName),
      retry: false,
    }),
    expectedAccesses = arr(accessesQuery.data?.items),
    functionalModelQuery = useQuery({
      queryKey: ["golden-functional", sourceName],
      queryFn: () => getJson(`golden-sources/${encoded}/functional-model`),
      enabled: Boolean(sourceName),
      retry: false,
    }),
    saveFunctional = useMutation({
      mutationFn: (body: Row) => postJson(`golden-sources/${encoded}/functional-model`, body),
      onSuccess: async (data) => {
        setFunctionalEditing(null);
        setNotice({ tone: "ok", text: `Golden V2 version v${s(data.version)} created` });
        await Promise.all([functionalModelQuery.refetch(), content.refetch(), q.refetch()]);
      },
      onError: (error) => setNotice({ tone: "error", text: s(error, "Unable to save the Golden V2 model") }),
    }),
    authQuery = useQuery({
      queryKey: ["golden-authentication", sourceName],
      queryFn: () => getJson(`golden-sources/${encoded}/authentication`),
      enabled: Boolean(sourceName),
      retry: false,
    }),
    authControls = arr(authQuery.data?.controls),
    authSummary = (authQuery.data?.summary ?? {}) as Row,
    adoptPosture = useMutation({
      mutationFn: () => postJson(`golden-sources/${encoded}/authentication`),
      onSuccess: async (d) => {
        setNotice({ tone: "ok", text: `Authentication policy recorded in v${s(d.version)}` });
        await c.invalidateQueries({ queryKey: ["golden-authentication"] });
        await refresh();
      },
      onError: (e) => setNotice({ tone: "error", text: s(e, "Unable to record the authentication policy") }),
    }),
    content = useQuery({
      queryKey: ["golden-assignments", sourceName, selected, limit, offset, sort, order, columns.key],
      queryFn: () =>
        getJson(`golden-sources/${encoded}/assignments`, {
          search: selected,
          limit,
          offset,
          sort,
          order,
          ...columns.params,
        }),
      enabled: Boolean(sourceName),
      retry: false,
    }),
    expected = arr(content.data?.items),
    history = arr(content.data?.versions),
    refresh = async () => {
      await Promise.all([
        q.refetch(),
        c.invalidateQueries({ queryKey: ["golden-assignments"] }),
        c.invalidateQueries({ queryKey: ["golden-accesses"] }),
      ]);
    },
    saveAccessRow = useMutation({
      mutationFn: async (body: Row) => {
        const accessId = s(body.access_id, "");
        if (accessId) {
          await putJson(`accesses/${encodeURIComponent(accessId)}/enrichment`, {
            application: s(body.application, ""),
            business_permission: s(body.business_permission, ""),
            owner: s(body.owner, ""),
          });
        }
        if (body.comment_dirty) {
          await postJson(`golden-sources/${encoded}/access-comment`, {
            access_provider: body.access_provider,
            access_name: body.access_name,
            comment: s(body.access_comment, ""),
          });
        }
        return body;
      },
      onSuccess: async () => {
        setEditingAccess(null);
        setNotice({ tone: "ok", text: "Expected access updated" });
        await refresh();
      },
      onError: (error) => setNotice({ tone: "error", text: s(error, "Unable to update expected access") }),
    }),
    createApplication = useMutation({
      mutationFn: (body: Row) => postJson("golden-applications", body),
      onSuccess: async (data) => {
        if (!data.created) {
          setNewApplication({ ...newApplication, similar: arr(data.similar) });
          return;
        }
        await applicationCatalog.refetch();
        if (editingAccess) setEditingAccess({ ...editingAccess, application: s(((data.application ?? {}) as Row).name) });
        setNewApplication(null);
      },
      onError: (error) => setNotice({ tone: "error", text: s(error, "Unable to create application") }),
    }),
    baseline = useMutation({
      mutationFn: () => postJson("golden-sources/baseline", { name, snapshot_id: sid, comment: globalComment }),
      onSuccess: async (d) => {
        setNotice({
          tone: "ok",
          text: `Baseline created · v${s((d.version as Row | undefined)?.version, "1")}`,
        });
        await refresh();
      },
      onError: (e) => setNotice({ tone: "error", text: s(e, "Unable to create the baseline") }),
    }),
    emptyGolden = useMutation({
      mutationFn: () => postJson("golden-sources/from-scratch", { name, display_name: name, comment: globalComment }),
      onSuccess: async (d) => {
        setNotice({ tone: "ok", text: `Empty Golden Source created · v${s((d.version as Row | undefined)?.version, "1")}` });
        await refresh();
      },
      onError: (e) => setNotice({ tone: "error", text: s(e, "Unable to create the Golden Source") }),
    }),
    edit = useMutation({
      mutationFn: (body: Row) => postJson(`golden-sources/${encoded}/assignments`, body),
      onSuccess: async (d) => {
        setAdding(null);
        setRemoving(null);
        setEditingHolder(null);
        setHolders(null);
        setNotice({
          tone: "ok",
          text: `Version v${s(d.version)} created · ${s(d.assignments)} expected access(es)`,
        });
        await refresh();
      },
      onError: (e) => setNotice({ tone: "error", text: s(e, "Unable to change the Golden Source") }),
    }),
    addExpectedAccess = useMutation({
      mutationFn: () => postJson(`golden-sources/${encoded}/functional-model`, {
        access_provider: s(adding?.access_provider, "").trim(),
        access_name: s(adding?.access_name, "").trim(),
        manual_access: true,
        access_display_name: s(adding?.access_name, "").trim(),
        access_type: "access",
        completeness: "not_defined",
        rights: [],
        grants: [],
        version_comment: "Expected access defined without an expected holder",
      }),
      onSuccess: async (data) => {
        setAdding(null);
        setNotice({ tone: "ok", text: `Expected access added in Golden v${s(data.version)}` });
        await refresh();
      },
      onError: (e) => setNotice({ tone: "error", text: s(e, "Unable to add the expected access") }),
    }),
    updateVersionComment = useMutation({
      mutationFn: () => postJson(`golden-sources/${encoded}/version-comment`, { comment: versionComment }),
      onSuccess: async (data) => {
        setEditingVersionComment(false);
        setNotice({ tone: "ok", text: `Golden version comment saved in v${s(data.version)}` });
        await refresh();
      },
      onError: (error) => setNotice({ tone: "error", text: s(error, "Unable to save the Golden version comment") }),
    }),
    commentAssignment = useMutation({
      mutationFn: () => postJson(`golden-sources/${encoded}/assignment-comment`, { ...commenting, comment: assignmentComment }),
      onSuccess: async (data) => {
        setCommenting(null);
        setAssignmentComment("");
        setNotice({ tone: "ok", text: `Comment saved in Golden v${s(data.version)}` });
        await refresh();
      },
      onError: (error) => setNotice({ tone: "error", text: s(error, "Unable to save the expected-assignment comment") }),
    }),
    commentAccess = useMutation({
      mutationFn: () => postJson(`golden-sources/${encoded}/access-comment`, {
        access_provider: accessCommenting?.access_provider,
        access_name: accessCommenting?.access_name,
        comment: accessComment,
      }),
      onSuccess: async () => {
        setAccessCommenting(null);
        setNotice({ tone: "ok", text: "Access comment saved" });
        await refresh();
      },
      onError: (error) => setNotice({ tone: "error", text: s(error, "Unable to save the access comment") }),
    }),
    compareMutation = useMutation({
      mutationFn: () => getJson(`golden-sources/${encoded}/compare`),
      onSuccess: (d) => {
        setCompare(d);
        setTab("changes");
        setNotice(null);
      },
      onError: (e) => setNotice({ tone: "error", text: s(e, "Unable to compare with the systems") }),
    }),
    confirm = useMutation({
      mutationFn: () =>
        postJson(`golden-sources/${encoded}/confirm-version`, {
          observed_snapshot_id: compare?.observed_snapshot_id,
          active_golden_version_id: compare?.active_golden_version_id,
        }),
      onSuccess: async (d) => {
        setCompare(null);
        setTab("expected");
        setNotice({
          tone: "ok",
          text: `Version v${s((d.version as Row | undefined)?.version)} is now the expected state`,
        });
        await refresh();
      },
      onError: (e) => setNotice({ tone: "error", text: s(e, "Unable to confirm this version") }),
    }),
    snapshots = [...arr(snap.data?.items)].sort((a, b) => s(a.created_at).localeCompare(s(b.created_at))),
    latest = snapshots[snapshots.length - 1],
    changes = arr(compare?.changes),
    covered = vals(content.data?.providers),
    collected = vals(content.data?.collected_providers),
    mismatch = covered.filter((name) => !collected.includes(name)),
    counted = (state: string) => changes.filter((r) => r.status === state).length;
  useEffect(() => setOffset(0), [selected]);
  useEffect(() => {
    if (!sid && latest) setSid(s(latest.id));
  }, [latest?.id]);
  return (
    <>
      <Head title="Golden Source">
        {source && (
          <div className="button-row">
            <a className="button subtle" href={`/api/golden-sources/${encoded}/export`}>
              Export CSV
            </a>
            <button
              className="button primary"
              onClick={() => compareMutation.mutate()}
              disabled={compareMutation.isPending}
            >
              {compareMutation.isPending ? "Comparing…" : "Compare with the systems"}
            </button>
          </div>
        )}
      </Head>
      <p className="muted">
        The Golden Source is the list of accesses that are <strong>expected</strong>. Everything the systems
        contain beyond this list is reported as unexpected, and everything missing from the systems is
        reported as missing.
      </p>
      {goldens.length > 1 && (
        <div className="filterbar">
          <select
            className="filter-button"
            value={sourceName}
            onChange={(e) => {
              setChosen(e.target.value);
              setCompare(null);
              setNotice(null);
            }}
          >
            {goldens.map((row) => (
              <option key={s(row.id)} value={s(row.name)}>
                {s(row.display_name, s(row.name))}
              </option>
            ))}
          </select>
        </div>
      )}
      {notice && notice.tone !== "ok" && mismatch.length ? (
        <section className="panel">
          <h2>This expected state cannot be compared with the latest collection</h2>
          <p>
            {s(source?.display_name, sourceName)} describes {covered.join(", ")}, but the latest collection
            only contains {collected.join(", ") || "nothing"}.
          </p>
          <p className="muted">
            Collect {mismatch.join(", ")} to compare the whole expected state, or open the expected state that
            matches what was collected.
          </p>
          <div className="button-row">
            <NavLink className="button subtle" to="/sources">
              Go to Sources &amp; IdPs
            </NavLink>
            {goldens
              .filter((row) => s(row.name) !== sourceName)
              .map((row) => (
                <button
                  className="button subtle"
                  key={s(row.id)}
                  onClick={() => {
                    setChosen(s(row.name));
                    setCompare(null);
                    setNotice(null);
                  }}
                >
                  Open {s(row.display_name, s(row.name))}
                </button>
              ))}
          </div>
        </section>
      ) : (
        notice && <p className={notice.tone === "ok" ? "form-success" : "form-error"}>{notice.text}</p>
      )}
      {!source ? (
        <section className="panel">
          <h2>No expected state yet</h2>
          <p>Define the expected access state from a collection, or start with an empty immutable version.</p>
          <div className="tabs compact-tabs">
            <button className={createMode === "snapshot" ? "text-button active" : "text-button"} onClick={() => setCreateMode("snapshot")}>From snapshot</button>
            <button className={createMode === "scratch" ? "text-button active" : "text-button"} onClick={() => setCreateMode("scratch")}>From scratch</button>
          </div>
          {createMode === "snapshot" && snapshots.length ? (
            <>
              <p>
                Start from what the systems contain today: EARE reads the latest collected state and declares
                it expected. You can then correct it access by access.
              </p>
              <p className="muted">
                Latest collection: {when(latest?.created_at)} ·{" "}
                {s(
                  arr(latest?.providers)
                    .map((x) => s(x.name))
                    .join(", "),
                  "source unknown",
                )}
              </p>
              <div className="admin-form">
                <label>
                  Name
                  <input value={name} onChange={(e) => setName(e.target.value)} />
                </label>
                <label>
                  Version comment
                  <textarea value={globalComment} onChange={(e) => setGlobalComment(e.target.value)} placeholder="Why this expected version exists" />
                </label>
                <label>
                  Collected state to adopt
                  <select value={sid} onChange={(e) => setSid(e.target.value)}>
                    {snapshots.map((r) => (
                      <option key={s(r.id)} value={s(r.id)}>
                        {when(r.created_at)} ·{" "}
                        {arr(r.providers)
                          .map((x) => s(x.name))
                          .join(", ")}
                      </option>
                    ))}
                  </select>
                </label>
                <button
                  className="button primary"
                  disabled={!sid || baseline.isPending}
                  onClick={() => baseline.mutate()}
                >
                  Adopt as expected state
                </button>
              </div>
            </>
          ) : createMode === "snapshot" ? (
            <>
              <p>Nothing has been collected yet, so there is no state to declare as expected.</p>
              <p className="muted">Synchronize a source first, then come back here.</p>
              <NavLink className="button subtle" to="/sources">
                Go to Sources &amp; IdPs
              </NavLink>
            </>
          ) : (
            <div className="admin-form">
              <label>
                Golden Source name
                <input value={name} onChange={(e) => setName(e.target.value)} />
              </label>
              <label>
                Version comment
                <textarea value={globalComment} onChange={(e) => setGlobalComment(e.target.value)} placeholder="Why this expected version exists" />
              </label>
              <button className="button primary" disabled={!name.trim() || emptyGolden.isPending} onClick={() => emptyGolden.mutate()}>
                Create empty Golden Source
              </button>
              <p className="field-note">Creates an immutable empty v1. Add expected assignments immediately afterwards.</p>
            </div>
          )}
        </section>
      ) : (
        <>
          <section className="panel golden-hero">
            <div className="golden-title">
              <div><span className="eyebrow">Golden Source</span><h2>{s(source.display_name, sourceName)}</h2></div>
              <Status v={`v${s(content.data?.version, "—")}`} />
            </div>
            <p className="muted">
              {content.data ? goldenOrigin(content.data as Row) : "Loading…"}
              {covered.length ? ` · covers ${covered.join(", ")}` : ""}
              {content.data?.comment ? ` · ${s(content.data.comment)}` : " · No version comment"}
              <button className="link-button" onClick={() => { setVersionComment(s(content.data?.comment, "")); setEditingVersionComment(true); }}>Edit version comment</button>
            </p>
            <div className="golden-metrics">
              <div><strong>{s(content.data?.assignment_count, "0")}</strong><span>Expected assignments</span></div>
              <div><strong>{s(content.data?.identity_count, "0")}</strong><span>Expected identities</span></div>
              <div><strong>{s(content.data?.access_count, "0")}</strong><span>Access rights</span></div>
              <div><strong>{s(content.data?.application_count, "0")}</strong><span>Applications</span></div>
            </div>
          </section>
          <div className="tabs">
            <button
              className={tab === "accesses" ? "text-button active" : "text-button"}
              onClick={() => setTab("accesses")}
            >
              Expected access rights
            </button>
            <button
              className={tab === "expected" ? "text-button active" : "text-button"}
              onClick={() => setTab("expected")}
            >
              Who holds them
            </button>
            <button
              className={tab === "changes" ? "text-button active" : "text-button"}
              onClick={() => setTab("changes")}
            >
              Changes since the last collection
            </button>
            <button
              className={tab === "functional" ? "text-button active" : "text-button"}
              onClick={() => setTab("functional")}
            >
              Functional model
            </button>
            <button
              className={tab === "authentication" ? "text-button active" : "text-button"}
              onClick={() => setTab("authentication")}
            >
              Authentication policy
            </button>
            <button
              className={tab === "catalog" ? "text-button active" : "text-button"}
              onClick={() => setTab("catalog")}
            >
              Application catalogue
            </button>
            <button
              className={tab === "history" ? "text-button active" : "text-button"}
              onClick={() => setTab("history")}
            >
              Version history
            </button>
          </div>
          {tab === "accesses" && (
            <>
              <Filter v={search} onChange={setSearch}>
                <button className="button subtle" onClick={() => setAdding(blankExpected())}>
                  + Add expected access
                </button>
              </Filter>
              <datalist id="golden-access-owners">
                {arr(ownerOptions.data?.items).map((row) => {
                  const owner = `${s(row.provider)}/${s(row.identifier, s(row.id))}`;
                  return <option key={owner} value={owner}>{s(row.display_name, owner)}</option>;
                })}
              </datalist>
              <Table
                className="golden-access-table"
                cols={[
                  "Access right",
                  "What it allows",
                  "Application",
                  "Permission",
                  "Owner",
                  "Source",
                  "Expected holders",
                  "Comment",
                  "Actions",
                ]}
                fields={[
                  "access_display_name",
                  "access_description",
                  "access_target",
                  "access_permission",
                  "access_owner",
                  "access_provider",
                  "expected_identities",
                  "access_comment",
                  null,
                ]}
                sorting={sorting}
                filtering={columns.filtering}
                q={accessesQuery}
                rows={expectedAccesses.map((r) => {
                  const key = `${s(r.access_provider)}:${s(r.access_name)}`;
                  const editing = editingAccess?.key === key;
                  const applicationOptions = Array.from(new Set([
                    ...arr(applicationCatalog.data?.applications as Row[] | undefined).map((option) => s(option.name)).filter(Boolean),
                    ...vals(accessesQuery.data?.application_options),
                  ]));
                  const capabilityOptions = arr(functionalModelQuery.data?.capabilities);
                  const permissionOptions = capabilityOptions.length
                    ? capabilityOptions.map((option) => s(option.id, s(option.label)))
                    : DEFAULT_GOLDEN_CAPABILITIES;
                  const application = contextValue(r.business_context, "application", "manual") || contextValue(r.business_context, "application", "source") || "";
                  const businessPermission = contextValue(r.business_context, "business_permission", "manual") || contextValue(r.business_context, "business_permission", "source") || "";
                  const owner = contextValue(r.business_context, "owner", "manual") || contextValue(r.business_context, "owner", "source") || s(r.access_owner, "");
                  const ownerDisplay = owner ? ownerDisplayLabel(owner, arr(ownerOptions.data?.items), s(r.access_provider)) : "";
                  const beginEdit = () => setEditingAccess({
                    key,
                    access_id: r.access_id,
                    access_provider: r.access_provider,
                    access_name: r.access_name,
                    application,
                    business_permission: businessPermission,
                    owner,
                    access_comment: s(r.access_comment, ""),
                    original_comment: s(r.access_comment, ""),
                  });
                  const applicationCell = editing
                    ? <select value={s(editingAccess?.application, "")} onChange={(event) => {
                        if (event.target.value === "__new_application__") setNewApplication({ name: "", comment: "", similar: [] });
                        else setEditingAccess({ ...editingAccess, application: event.target.value });
                      }}>
                        <option value="">Select application</option>
                        {applicationOptions.map((option) => <option key={option} value={option}>{option}</option>)}
                        <option value="__new_application__">+ Add new application</option>
                      </select>
                    : <button className="link-button" onClick={beginEdit}>{application || "—"}</button>;
                  const selectCell = (field: string, value: string, options: string[], placeholder: string) => editing
                    ? <select value={s(editingAccess?.[field], "")} onChange={(event) => setEditingAccess({ ...editingAccess, [field]: event.target.value })}>
                        <option value="">{placeholder}</option>
                        {options.map((option) => <option key={option} value={option}>{option}</option>)}
                      </select>
                    : <button className="link-button" onClick={beginEdit}>{value || "—"}</button>;
                  return [
                    <button className="link-button" onClick={() => setHolders(r)}>
                      {s(r.access_display_name, s(r.access_name))}
                    </button>,
                    <Sub>
                      {describeAccess({
                        description: r.access_description,
                        permission: r.access_permission,
                        target: r.access_target,
                      })}
                    </Sub>,
                    applicationCell,
                    selectCell("business_permission", businessPermission || "Not provided", permissionOptions, "Select permission"),
                    editing ? (
                      <select value={s(editingAccess?.owner, "")} onChange={(event) => setEditingAccess({ ...editingAccess, owner: event.target.value })}>
                        <option value="">Select owner</option>
                        {arr(ownerOptions.data?.items).map((identity) => {
                          const identifier = s(identity.identifier, s(identity.id));
                          const value = `${s(identity.provider)}/${identifier}`;
                          return <option key={value} value={value}>{s(identity.provider)}/{s(identity.display_name, identifier)}</option>;
                        })}
                      </select>
                    ) : <button className="link-button" onClick={beginEdit}>{ownerDisplay || "—"}</button>,
                    s(r.access_provider),
                    <button className="link-button" onClick={() => setHolders(r)}>
                      {s(r.expected_identities, "0")} people
                    </button>,
                    <button className="link-button" onClick={() => { setAccessCommenting(r); setAccessComment(s(r.access_comment, "")); }}>
                      {s(r.access_comment, "Add comment")}
                    </button>,
                    <button
                      className="link-button"
                      onClick={() => setRemoving({
                        access_display_name: r.access_display_name,
                        access_name: r.access_name,
                        access_provider: r.access_provider,
                        remove_access: true,
                        remove_assignments: arr(r.identities).map((identity) => ({
                          access_provider: r.access_provider,
                          access_name: r.access_name,
                          identity_provider: identity.identity_provider,
                          identity_identifier: identity.identity_identifier,
                        })),
                      })}
                    >Remove</button>,
                  ];
                })}
              />
              <Pager
                total={Number(accessesQuery.data?.total ?? 0)}
                limit={limit}
                offset={offset}
                setOffset={setOffset}
                setLimit={setLimit}
              />
            </>
          )}
          {tab === "expected" && (
            <>
              <Filter v={search} onChange={setSearch}>
                <button className="button subtle" onClick={() => setAdding(blankExpected())}>
                  + Add expected access
                </button>
              </Filter>
              <Table
                cols={["Identity", "Access", "Application", "Permission", "Golden comment", "Source", "Actions"]}
                fields={[
                  "identity_display_name",
                  "access_display_name",
                  "business_context",
                  "business_context",
                  "golden_comment",
                  "access_provider",
                  null,
                ]}
                sorting={sorting}
                filtering={columns.filtering}
                q={content}
                rows={expected.map((r) => {
                  const key = `${s(r.access_provider)}:${s(r.access_name)}:${s(r.identity_provider)}:${s(r.identity_identifier)}`;
                  const editing = editingHolder?.key === key;
                  return [
                    editing ? (
                      <div className="inline-edit-stack">
                        <select value={s(editingHolder?.identity_provider, "")} onChange={(event) => setEditingHolder({ ...editingHolder, identity_provider: event.target.value, identity_identifier: "" })}>
                          <option value="">Select source</option>
                          {arr(providerOptions.data?.items).map((provider) => <option key={s(provider.name)} value={s(provider.name)}>{s(provider.display_name, s(provider.name))}</option>)}
                        </select>
                        <select value={s(editingHolder?.identity_identifier, "")} onChange={(event) => setEditingHolder({ ...editingHolder, identity_identifier: event.target.value })}>
                          <option value="">Select holder</option>
                          {arr(holderIdentityOptions.data?.items).map((identity) => {
                            const identifier = s(identity.identifier, s(identity.id));
                            return <option key={identifier} value={identifier}>{s(identity.display_name, identifier)}</option>;
                          })}
                        </select>
                      </div>
                    ) : s(r.identity_display_name, s(r.identity_identifier)),
                    s(r.access_display_name, s(r.access_name)),
                    contextValue(r.business_context, "application", "manual") || contextValue(r.business_context, "application", "source") || "Unknown",
                    contextValue(r.business_context, "business_permission", "manual") || contextValue(r.business_context, "business_permission", "source") || "Not provided",
                    <button className="link-button" onClick={() => { setCommenting(r); setAssignmentComment(s(r.golden_comment, "")); }}>
                      {s(r.golden_comment, "Add comment")}
                    </button>,
                    s(r.access_provider),
                    <div className="row-actions">
                      {editing ? <>
                        <button className="link-button" disabled={edit.isPending || !s(editingHolder?.identity_provider, "") || !s(editingHolder?.identity_identifier, "")} onClick={() => edit.mutate({
                          remove: [{ access_provider: r.access_provider, access_name: r.access_name, identity_provider: r.identity_provider, identity_identifier: r.identity_identifier, access_native_id: r.access_native_id, access_permission: r.access_permission, identity_native_id: r.identity_native_id }],
                          add: [{ access_provider: r.access_provider, access_name: r.access_name, identity_provider: editingHolder?.identity_provider, identity_identifier: editingHolder?.identity_identifier, access_native_id: r.access_native_id, access_permission: r.access_permission, identity_native_id: editingHolder?.identity_native_id }],
                        })}>Save</button>
                        <button className="link-button" onClick={() => setEditingHolder(null)}>Cancel</button>
                      </> : <button className="link-button" onClick={() => setEditingHolder({ ...r, key, original_identity_provider: r.identity_provider, original_identity_identifier: r.identity_identifier })}>Edit</button>}
                      {!editing ? <button className="link-button" onClick={() => setRemoving(r)}>Remove</button> : null}
                    </div>,
                  ];
                })}
              />
              <Pager
                total={Number(content.data?.total ?? 0)}
                limit={limit}
                offset={offset}
                setOffset={setOffset}
                setLimit={setLimit}
              />
            </>
          )}
          {tab === "changes" && (
            <section className="panel">
              {!compare ? (
                <>
                  <h2>Nothing compared yet</h2>
                  <p>
                    Compare the expected state with what the systems contain today. Comparing changes nothing
                    on its own.
                  </p>
                  <button
                    className="button primary"
                    onClick={() => compareMutation.mutate()}
                    disabled={compareMutation.isPending}
                  >
                    Compare with the systems
                  </button>
                </>
              ) : (
                <>
                  <h2>What changed from the expected state?</h2>
                  <div className="diff-summary">
                    <span><strong>{counted("added")}</strong> Unexpected</span>
                    <span><strong>{counted("removed")}</strong> Missing</span>
                    <span><strong>{counted("unchanged")}</strong> Unchanged</span>
                  </div>
                  <Table
                    cols={["Change", "Identity", "Access", "Source"]}
                    rows={changes
                      .filter((r) => r.status !== "unchanged")
                      .map((r) => [
                        <Status v={r.status === "added" ? "unexpected" : "missing"} />,
                        s(r.identity_identifier),
                        s(r.access_name),
                        s(r.access_provider),
                      ])}
                  />
                  <p className="muted">
                    Confirming records a new expected version containing exactly what the systems contain
                    today. The previous version is kept in the history.
                  </p>
                  <button
                    className="button primary"
                    onClick={() => confirm.mutate()}
                    disabled={confirm.isPending || counted("added") + counted("removed") === 0}
                  >
                    Accept these changes as expected
                  </button>
                </>
              )}
            </section>
          )}
          {tab === "functional" && (
            <section className="panel">
              <h2>Source-informed Golden V2 suggestions</h2>
              <p className="muted">Observed and mapped values are suggestions only. Review and explicitly enter the validated values in the Golden model; source observations never rewrite expected truth.</p>
              {functionalModelQuery.isError ? <p className="form-error">{s(functionalModelQuery.error)}</p> : null}
              <GoldenFunctionalSuggestions
                rows={arr(functionalModelQuery.data?.items)}
                onEdit={(row) => {
                  const suggestion = (row.canonical_suggestions ?? {}) as Row;
                  const target = (suggestion.target ?? {}) as Row;
                  const service = (target.service ?? {}) as Row;
                  const resource = (target.resource ?? {}) as Row;
                  const mapped = vals(suggestion.mapped_capability_ids);
                  setFunctionalEditing({
                    access_provider: row.access_provider,
                    access_name: row.access_name,
                    access_display_name: row.access_display_name,
                    completeness: row.completeness === "not_defined" ? "partial" : row.completeness,
                    capability_id: mapped[0] ?? "",
                    service_identifier: service.identifier ?? "",
                    resource_identifier: resource.identifier ?? "",
                    service_display_name: service.display_name ?? "",
                    resource_display_name: resource.display_name ?? "",
                    version_comment: "Validate source-informed functional model",
                  });
                }}
              />
            </section>
          )}
          {tab === "authentication" && (
            <>
              <section className="panel">
                <div className="panel-title">
                  <h2>How people are expected to authenticate</h2>
                  <span className="muted">
                    {authQuery.data?.collected_at
                      ? `observed ${when(authQuery.data.collected_at)}`
                      : "nothing observed yet"}
                  </span>
                </div>
                {authQuery.data?.expected ? (
                  <div className="diff-summary">
                    <strong>{s(authSummary.compliant, "0")} as expected</strong>
                    <strong>{s(authSummary.deviation, "0")} deviation(s)</strong>
                    <strong>{s(authSummary.unknown, "0")} not collected</strong>
                  </div>
                ) : (
                  <p>
                    This expected state declares no authentication policy, so nothing is checked against what
                    the systems enforce.
                  </p>
                )}
                <p className="muted">
                  Controls cover password rules, multi-factor authentication, federation and tokens, as
                  reported by the collection.
                </p>
                <button
                  className="button subtle"
                  disabled={adoptPosture.isPending}
                  onClick={() => adoptPosture.mutate()}
                >
                  {authQuery.data?.expected
                    ? "Replace with the observed posture"
                    : "Adopt the observed posture as expected"}
                </button>
              </section>
              <Table
                cols={["Control", "Expected", "Observed", "Assessment"]}
                q={authQuery}
                rows={authControls.map((r) => [
                  s(r.control).replaceAll("_", " "),
                  s(r.expected),
                  s(r.observed),
                  <Status
                    v={
                      s(r.assessment) === "compliant"
                        ? "expected_and_observed"
                        : s(r.assessment) === "deviation"
                          ? "unexpected"
                          : s(r.assessment)
                    }
                  />,
                ])}
              />
            </>
          )}
          {tab === "catalog" && (
            <section className="panel">
              <div className="panel-title">
                <div>
                  <h2>Application catalogue</h2>
                  <p className="muted">Shared business applications used to enrich Golden access rights. Historical usage protects applications from deletion.</p>
                </div>
                <button className="button primary" onClick={() => setNewApplication({ name: "", comment: "", similar: [] })}>
                  + Add application
                </button>
              </div>
              {applicationCatalog.isError ? <p className="form-error">{s(applicationCatalog.error, "Unable to load the application catalogue")}</p> : null}
              <Table
                cols={["Application", "Comment", "Status", "Golden usage"]}
                rows={arr(applicationCatalog.data?.applications).map((application) => [
                  <strong>{s(application.name)}</strong>,
                  s(application.comment, ""),
                  application.active === false ? <Status v="inactive" /> : <Status v="active" />,
                  s(application.usage_count, "0"),
                ])}
              />
              {!arr(applicationCatalog.data?.applications).length && !applicationCatalog.isLoading ? <p className="muted">No applications in the catalogue yet.</p> : null}
            </section>
          )}
          {tab === "history" && (
            <Table
              cols={["Version", "Origin", "Created", "Expected access"]}
              q={content}
              rows={[...history]
                .reverse()
                .map((r) => [
                  <strong>v{s(r.version)}</strong>,
                  goldenOrigin(r),
                  when(r.created_at),
                  s(r.assignments, "0"),
                ])}
            />
          )}
        </>
      )}
      {holders && (
        <Drawer title={s(holders.access_display_name, s(holders.access_name))} close={() => setHolders(null)} size="wide">
          <p>
            {describeAccess({
              description: holders.access_description,
              permission: holders.access_permission,
              target: holders.access_target,
            }) || "The source provided no description for this access."}
          </p>
          <p className="muted">
            {s(holders.access_provider)}
            {targetText(holders.access_target) ? ` · ${targetText(holders.access_target)}` : ""}
            {s(holders.access_permission, "") ? ` · ${s(holders.access_permission)}` : ""}
          </p>
          <AccessDetail access={{ ...holders, provider: holders.access_provider, name: holders.access_name, id: holders.access_id, permission: { identifier: holders.access_permission } }} />
          <h4>DESCRIPTION</h4>
          <p>{s(holders.access_description, "No description was provided for this access.")}</p>
        </Drawer>
      )}
      {newApplication && (
        <Drawer title="Add new application" close={() => setNewApplication(null)}>
          <p className="muted">Create a catalogue entry. The comment explains the business scope of this application.</p>
          <label>Application name<input autoFocus value={s(newApplication.name, "")} onChange={(event) => setNewApplication({ ...newApplication, name: event.target.value })} /></label>
          <label>Comment<textarea value={s(newApplication.comment, "")} onChange={(event) => setNewApplication({ ...newApplication, comment: event.target.value })} /></label>
          {arr(newApplication.similar).length ? (
            <div className="attention">
              <strong>Similar applications found</strong>
              <p>{arr(newApplication.similar).map((item) => `${s(item.name)} (${s(item.score)})`).join(", ")}</p>
              <p className="muted">Saving again will create this application explicitly.</p>
            </div>
          ) : null}
          <button
            className="button primary"
            disabled={createApplication.isPending || !s(newApplication.name).trim()}
            onClick={() => createApplication.mutate({ name: s(newApplication.name).trim(), comment: s(newApplication.comment).trim(), confirm: arr(newApplication.similar).length > 0 })}
          >
            {createApplication.isPending ? "Saving…" : arr(newApplication.similar).length ? "Create anyway" : "Create application"}
          </button>
        </Drawer>
      )}
      {functionalEditing && (
        <Drawer title={`Validate Golden V2 · ${s(functionalEditing.access_display_name, s(functionalEditing.access_name))}`} close={() => setFunctionalEditing(null)}>
          <p className="muted">Observed and mapped values are prefilled for review. Saving creates a new immutable expected version; it does not rewrite the source observation.</p>
          <label>Completeness<select value={s(functionalEditing.completeness, "partial")} onChange={(event) => setFunctionalEditing({ ...functionalEditing, completeness: event.target.value })}>
            <option value="not_defined">Not defined</option><option value="partial">Partial</option><option value="complete">Complete</option>
          </select></label>
          <label>Capability<select required value={s(functionalEditing.capability_id, "")} onChange={(event) => setFunctionalEditing({ ...functionalEditing, capability_id: event.target.value })}>
            <option value="">Select a capability</option>
            {(arr(functionalModelQuery.data?.capabilities).length ? arr(functionalModelQuery.data?.capabilities).map((capability) => ({ id: s(capability.id), label: s(capability.label, s(capability.id)) })) : DEFAULT_GOLDEN_CAPABILITIES.map((id) => ({ id, label: id }))).map((capability) => <option key={capability.id} value={capability.id}>{capability.label}</option>)}
          </select></label>
          <label>Target service<input value={s(functionalEditing.service_identifier, "")} onChange={(event) => setFunctionalEditing({ ...functionalEditing, service_identifier: event.target.value })} /></label>
          <label>Target resource<input value={s(functionalEditing.resource_identifier, "")} onChange={(event) => setFunctionalEditing({ ...functionalEditing, resource_identifier: event.target.value })} /></label>
          <label>Version comment<textarea value={s(functionalEditing.version_comment, "")} onChange={(event) => setFunctionalEditing({ ...functionalEditing, version_comment: event.target.value })} /></label>
          <button
            className="button primary"
            disabled={saveFunctional.isPending || !s(functionalEditing.capability_id, "") || (!s(functionalEditing.service_identifier, "") && !s(functionalEditing.resource_identifier, ""))}
            onClick={() => saveFunctional.mutate({
              access_provider: functionalEditing.access_provider,
              access_name: functionalEditing.access_name,
              manual_access: false,
              completeness: functionalEditing.completeness,
              rights: [{
                target: {
                  ...(s(functionalEditing.service_identifier, "") ? { service: { identifier: s(functionalEditing.service_identifier), display_name: s(functionalEditing.service_display_name, s(functionalEditing.service_identifier)), type: "application" } } : {}),
                  ...(s(functionalEditing.resource_identifier, "") ? { resource: { identifier: s(functionalEditing.resource_identifier), display_name: s(functionalEditing.resource_display_name, s(functionalEditing.resource_identifier)), type: "business_object" } } : {}),
                },
                capability_id: functionalEditing.capability_id,
              }],
              grants: [],
              version_comment: functionalEditing.version_comment,
            })}
          >
            {saveFunctional.isPending ? "Saving…" : "Validate and save Golden V2"}
          </button>
        </Drawer>
      )}
      {editingVersionComment && (
        <Drawer title="Golden version comment" close={() => setEditingVersionComment(false)}>
          <p className="muted">Explain this expected version. Saving creates a new immutable version and keeps its assignments and assignment comments.</p>
          <label>Version comment<textarea value={versionComment} onChange={(event) => setVersionComment(event.target.value)} /></label>
          <button className="button primary" disabled={updateVersionComment.isPending} onClick={() => updateVersionComment.mutate()}>Save in new version</button>
        </Drawer>
      )}
      {commenting && (
        <Drawer title="Expected-assignment comment" close={() => setCommenting(null)}>
          <p><strong>{s(commenting.identity_display_name, s(commenting.identity_identifier))}</strong> → {s(commenting.access_display_name, s(commenting.access_name))}</p>
          <p className="muted">Explain why this identity should have this access. Saving creates a new immutable Golden version.</p>
          <label>
            Golden comment
            <textarea value={assignmentComment} onChange={(event) => setAssignmentComment(event.target.value)} />
          </label>
          <button className="button primary" disabled={commentAssignment.isPending} onClick={() => commentAssignment.mutate()}>Save in new version</button>
        </Drawer>
      )}
      {accessCommenting && (
        <Drawer title="Golden access comment" close={() => setAccessCommenting(null)}>
          <p><strong>{s(accessCommenting.access_display_name, s(accessCommenting.access_name))}</strong></p>
          <p className="muted">This comment explains the business meaning of the access right.</p>
          <label className="drawer-field">
            Comment
            <textarea className="drawer-comment" autoFocus value={accessComment} onChange={(event) => setAccessComment(event.target.value)} />
          </label>
          <div className="drawer-actions">
            <button className="button subtle" onClick={() => setAccessCommenting(null)}>Cancel</button>
            <button className="button primary" disabled={commentAccess.isPending} onClick={() => commentAccess.mutate()}>Save</button>
          </div>
        </Drawer>
      )}
      {adding && (
        <Drawer title="Add an expected access" close={() => setAdding(null)} size="wide">
          <p className="muted">
            Declaring an access expected creates a new version. Nothing changes in the audited systems.
          </p>
          <datalist id="golden-assignment-providers">
            {arr(providerOptions.data?.items).map((row) => {
              const provider = s(row.name, s(row.provider));
              return <option key={provider} value={provider}>{s(row.display_name, provider)}</option>;
            })}
          </datalist>
          <datalist id="golden-assignment-identities">
            {arr(identityOptions.data?.items).map((row) => {
              const identifier = s(row.identifier, s(row.id));
              return <option key={identifier} value={identifier}>{s(row.display_name, identifier)}</option>;
            })}
          </datalist>
          <datalist id="golden-assignment-accesses">
            {arr(accessOptions.data?.items).map((row) => {
              const access = s(row.name, s(row.access_name));
              return <option key={access} value={access}>{s(row.display_name, access)}</option>;
            })}
          </datalist>
          <datalist id="golden-assignment-permissions">
            {arr(accessOptions.data?.items).map((row) => {
              const permission = s(row.access_permission, typeof row.permission === "string" ? row.permission : "");
              return permission ? <option key={`${s(row.name, s(row.access_name))}:${permission}`} value={permission} /> : null;
            })}
          </datalist>
          <p className="field-note">Les listes proposent les valeurs déjà connues. Une valeur manuelle reste possible si elle est validée métier.</p>
          <form
            className="drawer-form"
            onSubmit={(e) => {
              e.preventDefault();
              if (s(adding.identity_identifier, "").trim()) edit.mutate({ add: [adding] });
              else addExpectedAccess.mutate();
            }}
          >
            <label>
              Expected holder (optional)
              <input
                list="golden-assignment-identities"
                placeholder="alice.martin"
                value={s(adding.identity_identifier, "")}
                onChange={(e) => setAdding({ ...adding, identity_identifier: e.target.value })}
              />
            </label>
            <label>
              Holder source (optional)
              <input
                list="golden-assignment-providers"
                placeholder="corp-ad"
                value={s(adding.identity_provider, "")}
                onChange={(e) => setAdding({ ...adding, identity_provider: e.target.value })}
              />
            </label>
            <label>
              Access
              <input
                required
                list="golden-assignment-accesses"
                placeholder="GRP-Finance-RW"
                value={s(adding.access_name, "")}
                onChange={(e) => setAdding({ ...adding, access_name: e.target.value })}
              />
            </label>
            <label>
              Access source
              <input
                required
                list="golden-assignment-providers"
                placeholder="corp-ad"
                value={s(adding.access_provider, "")}
                onChange={(e) => setAdding({ ...adding, access_provider: e.target.value })}
              />
            </label>
            <label>
              Permission
              <input
                list="golden-assignment-permissions"
                value={s(adding.access_permission, "")}
                onChange={(e) => setAdding({ ...adding, access_permission: e.target.value })}
              />
            </label>
            <p className="field-note">No holder? The access will still be added to the expected state, and you can assign one or more holders later from <strong>Who holds them</strong>.</p>
            <button className="button primary" type="submit" disabled={edit.isPending || addExpectedAccess.isPending}>
              Add to the expected state
            </button>
          </form>
        </Drawer>
      )}
      {removing && (
        <Confirm
          title="Remove this expected access?"
          intro={
            <>
              <p>
                {removing.remove_access
                  ? `${s(removing.access_display_name, s(removing.access_name))} and all its expected holders will be removed from the Golden Source.`
                  : `${s(removing.identity_display_name, s(removing.identity_identifier))} → ${s(removing.access_display_name, s(removing.access_name))} (${s(removing.access_provider)}) stops being expected.`}
                {removing.remove_access ? " If the systems still grant it, the next review reports it as unexpected." : " If the systems still grant it, the next review reports it as unexpected."}
              </p>
              <p className="muted">A new version is recorded. The current one stays in the history.</p>
            </>
          }
          confirmLabel="Remove from the expected state"
          danger
          pending={edit.isPending}
          cancel={() => setRemoving(null)}
          confirm={() => edit.mutate({ remove: removing.remove_assignments ?? [removing] })}
        />
      )}
    </>
  );
}
function SourceBrowser() {
  const { provider = "" } = useParams(),
    [kind, setKind] = useState("group"),
    [search, setSearch] = useState(""),
    [offset, setOffset] = useState(0),
    [selected, setSelected] = useState<Row | null>(null),
    [parents, setParents] = useState<string[]>([]),
    sourceConfig = useQuery({
      queryKey: ["source-browser-config", provider],
      queryFn: () => getJson("system/sources"),
      retry: false,
    }),
    source = arr(sourceConfig.data?.sources).find((row) => s(row.provider) === provider),
    treeEnabled = s(source?.type) === "openldap",
    currentParent = parents[parents.length - 1] ?? "",
    tree = useQuery({
      queryKey: ["source-tree", provider, currentParent],
      queryFn: () => getJson(`system/sources/${encodeURIComponent(provider)}/inspect/tree`, { parent: currentParent, limit: 100 }),
      enabled: treeEnabled,
      retry: false,
    }),
    query = useQuery({
      queryKey: ["source-browser", provider, kind, search, offset],
      queryFn: () => getJson(`system/sources/${encodeURIComponent(provider)}/inspect/objects`, { kind, search, limit: 25, offset }),
      enabled: Boolean(provider),
    }),
    selectedKind = selected?.kind === "user" || selected?.kind === "group" ? s(selected.kind) : kind,
    detail = useQuery({
      queryKey: ["source-object", provider, selectedKind, selected?.identifier],
      queryFn: () => getJson(`system/sources/${encodeURIComponent(provider)}/inspect/objects/${selectedKind}/${encodeURIComponent(s(selected?.identifier, ""))}`),
      enabled: Boolean(selected?.identifier),
    }),
    discovery = useQuery({
      queryKey: ["source-attributes", provider, kind],
      queryFn: () => getJson(`system/sources/${encodeURIComponent(provider)}/inspect/attributes`, { kind }),
      enabled: Boolean(provider),
    }),
    items = arr(query.data?.items),
    treeItems = arr(tree.data?.items),
    attributes = ((detail.data?.attributes ?? {}) as Row);
  return (
    <>
      <Head title={`Browse source · ${provider}`}>
        <NavLink className="button subtle" to="/sources"><ArrowLeft size={15} /> Sources</NavLink>
      </Head>
      <p className="muted">Read-only, bounded inspection. EARE cannot create, edit, rename or delete directory objects here.</p>
      {treeEnabled ? (
        <section className="panel">
          <div className="panel-title">
            <h2>LDAP directory tree</h2>
            <span className="muted">One level loaded at a time</span>
          </div>
          <div className="button-row">
            <button className="button subtle" disabled={!parents.length} onClick={() => { setParents((value) => value.slice(0, -1)); setSelected(null); }}>Up</button>
            <button className="button subtle" onClick={() => { setParents([]); setSelected(null); }}>{s(tree.data?.root, "Configured base")}</button>
            {parents.map((parent, index) => <button className="link-button" key={parent} onClick={() => { setParents(parents.slice(0, index + 1)); setSelected(null); }}>{parent.split(",", 1)[0]}</button>)}
          </div>
          {tree.isLoading ? <p>Loading directory level…</p> : treeItems.length ? (
            <div className="browser-layout">
              <div>
                {treeItems.map((item) => (
                  <button className="browser-row" key={s(item.identifier)} onClick={() => {
                    if (item.expandable) setParents([...parents, s(item.technical_identifier)]);
                    else if (item.selectable) setSelected(item);
                  }}>
                    <ChevronRight size={15} style={{ opacity: item.expandable ? 1 : 0.25 }} />
                    <span><strong>{s(item.display_name, s(item.technical_identifier))}</strong><small>{s(item.kind)} · {s(item.technical_identifier)}</small></span>
                  </button>
                ))}
              </div>
            </div>
          ) : <p className="muted">This directory level is empty.</p>}
          {tree.isError ? <p className="form-error">{s(tree.error, "Unable to browse this LDAP level")}</p> : null}
        </section>
      ) : null}
      <div className="filterbar">
        <select value={kind} onChange={(event) => { setKind(event.target.value); setOffset(0); setSelected(null); }}>
          <option value="group">Groups / access objects</option>
          <option value="user">Users / identities</option>
        </select>
        <input type="search" placeholder="Search this source" value={search} onChange={(event) => { setSearch(event.target.value); setOffset(0); }} />
      </div>
      <div className="browser-layout">
        <section className="panel">
          <h2>{kind === "group" ? "Groups" : "Users"}</h2>
          {query.isLoading ? <p>Loading…</p> : items.length ? items.map((item) => (
            <button className="browser-row" key={s(item.identifier)} onClick={() => setSelected(item)}>
              <strong>{s(item.display_name)}</strong><small>{s(item.technical_identifier)}</small>
            </button>
          )) : <p className="muted">No matching objects.</p>}
          {query.isError ? <p className="form-error">{s(query.error)}</p> : null}
          <div className="button-row">
            <button disabled={!offset} onClick={() => setOffset(Math.max(0, offset - 25))}>Previous</button>
            <button disabled={!query.data?.has_more} onClick={() => setOffset(offset + 25)}>Next</button>
          </div>
        </section>
        <section className="panel">
          <h2>{selected ? s(selected.display_name) : "Select an object"}</h2>
          {detail.isLoading ? <p>Loading attributes…</p> : selected ? (
            <div className="attribute-list">
              {Object.entries(attributes).map(([name, values]) => (
                <div key={name}><strong>{name}</strong><span>{vals(values).join(", ")}</span></div>
              ))}
            </div>
          ) : <p className="muted">Safe source attributes will appear here.</p>}
          {detail.isError ? <p className="form-error">{s(detail.error)}</p> : null}
        </section>
      </div>
      <section className="panel">
        <h2>Known and sampled safe source fields</h2>
        <p className="muted">Suggestions include common and configured fields plus safe sampled values. Coverage means populated in this bounded sample only; it does not verify permissions or application access.</p>
        <div className="attribute-list">
          {Object.entries((discovery.data?.attributes ?? {}) as Row).map(([name, info]) => {
            const row = info as Row;
            return <div key={name}><strong>{name}</strong><span>{s(row.coverage, "0")}% populated · {vals(row.samples).join(", ") || "No sample value"}</span></div>;
          })}
        </div>
      </section>
    </>
  );
}
export function sourceSupportsAttributeMapping(capabilities: unknown, connectorType: unknown): boolean {
  const declared = capabilities as Row | null | undefined;
  return typeof declared?.attribute_mapping === "boolean"
    ? declared.attribute_mapping
    : ["active_directory", "openldap"].includes(s(connectorType, "active_directory"));
}

function Sources({ principal }: { principal: Principal }) {
  const toast = useToast(),
    q = useQuery({ queryKey: ["providers"], queryFn: () => getPage("providers", { limit: 100 }) }),
    cfg = useQuery({ queryKey: ["source-configs"], queryFn: () => getJson("system/sources") }),
    [job, setJob] = useState(""),
    [kind, setKind] = useState("preview"),
    [error, setError] = useState(""),
    [editing, setEditing] = useState<Row | null>(null),
    [testResult, setTestResult] = useState<Row | null>(null),
    start = useMutation({
      mutationFn: (x: { p: string; a: string }) => postJson(`sources/${x.p}/${x.a}`),
      onSuccess: (d, variables) => {
        setError("");
        setJob(s(d.id));
        toast("ok", variables.a === "sync" ? "Synchronization started" : "Preview started");
      },
      onError: (e) => {
        setError(s(e, "Unable to start source operation"));
        toast("error", s(e, "Unable to start this source operation"));
      },
    }),
    save = useMutation({
      mutationFn: (body: Row) => postJson("system/sources", body),
      onSuccess: async () => {
        setEditing(null);
        setError("");
        await cfg.refetch();
        await q.refetch();
      },
      onError: (e) => setError(s(e, "Unable to save source configuration")),
    }),
    test = useMutation({
      mutationFn: (body: Row) => postJson("system/sources/test", body),
      onSuccess: (d) => {
        setError("");
        setTestResult(d);
        toast("ok", s(d.message, "Connection test succeeded"));
      },
      onError: (e) => {
        setError(s(e, "Source connection test failed"));
        toast("error", s(e, "Source connection test failed"));
      },
    }),
    jq = useQuery({
      queryKey: ["job", job],
      queryFn: () => getJson(`jobs/${job}`),
      enabled: !!job,
      refetchInterval: 1500 as const,
    }),
    sourceFields = useQuery({
      queryKey: ["source-field-picker", editing?.provider],
      queryFn: () => getJson(`system/sources/${encodeURIComponent(s(editing?.provider, ""))}/inspect/attributes`, { kind: "group" }),
      enabled: principal.role === "ADMIN" && Boolean(editing?.provider) && arr(cfg.data?.sources).some((row) => s(row.provider) === s(editing?.provider)),
      retry: false,
    }),
    configs = arr(cfg.data?.sources),
    observed = arr(q.data?.items),
    sources = configs.map((c): Row => ({
      health: "never_synced",
      ...c,
      ...(observed.find((o) => s(o.name) === s(c.provider)) || {}),
    }));
  useEffect(() => {
    if (jq.data?.status === "SUCCEEDED") void q.refetch();
  }, [jq.data?.status]);
  const blank = () => ({
    provider: "",
    type: "active_directory",
    connection: { server: "" },
    collection: { timeout: 300, allow_partial: false },
    credentials: { username_env: "", password_env: "" },
    business_mapping: Object.fromEntries(["display_name", "description", "application", "business_permission", "resource", "owner"].map((field) => [field, { mode: "default" }])),
  });
  const edit = (source?: Row) => {
    setError("");
    setTestResult(null);
    setEditing(source ? JSON.parse(JSON.stringify(source)) : blank());
  };
  const update = (key: string, value: unknown) => setEditing((x) => (x ? { ...x, [key]: value } : x));
  const updateNested = (section: string, key: string, value: unknown) =>
    setEditing((x) => (x ? { ...x, [section]: { ...((x[section] as Row) || {}), [key]: value } } : x));
  const updateMapping = (field: string, key: string, value: unknown) =>
    setEditing((current) => {
      if (!current) return current;
      const mapping = (current.business_mapping ?? {}) as Row;
      return { ...current, business_mapping: { ...mapping, [field]: { ...((mapping[field] ?? {}) as Row), [key]: value } } };
    });
  const supportsAttributeMapping = sourceSupportsAttributeMapping(editing?.capabilities, editing?.type);
  return (
    <>
      <Head title="Sources & IdPs">
        <button className="button primary" onClick={() => edit()}>
          + Add source
        </button>
      </Head>
      <p>
        Connect and monitor the identity and access systems EARE audits. Secrets remain referenced through
        environment variables and are never stored in the WebUI.
      </p>
      {!cfg.isLoading && !configs.length && (
        <section className="panel">
          <h2>No collection source is configured.</h2>
          <p>
            Use <strong>+ Add source</strong> to configure Active Directory or OpenLDAP.
          </p>
        </section>
      )}
      <div className="source-grid">
        {sources.map((r) => (
          <div className="source-card" key={s(r.provider)}>
            <div className="source-top">
              <Status v={r.health} />
              <span>{r.last_sync ? when(r.last_sync) : "Never collected"}</span>
            </div>
            <h2>{s(r.display_name, s(r.provider))}</h2>
            <p>
              {s(r.type).toUpperCase()} · {s(r.provider)}
            </p>
            <div className="source-stats">
              <div>
                <strong>{r.latest_snapshot ? s(r.identity_count, "—") : "—"}</strong>
                <span>Identities</span>
              </div>
              <div>
                <strong>{r.latest_snapshot ? s(r.group_count, "—") : "—"}</strong>
                <span>Groups</span>
              </div>
              <div>
                <strong>{r.latest_snapshot ? s(r.access_count, "—") : "—"}</strong>
                <span>Accesses</span>
              </div>
            </div>
            <div className="source-foot">
              {principal.role === "ADMIN" && Boolean((r.capabilities as Row | undefined)?.source_browser) ? <NavLink className="button subtle" to={`/sources/${encodeURIComponent(s(r.provider))}/browse`}>Browse source</NavLink> : null}
              <button
                className="button subtle"
                onClick={() => edit(configs.find((c) => s(c.provider) === s(r.provider)))}
              >
                Configure
              </button>
              <button
                className="button subtle"
                onClick={() => {
                  setKind("preview");
                  start.mutate({ p: s(r.provider), a: "preview" });
                }}
              >
                Preview
              </button>
              <button
                className="button primary"
                onClick={() => {
                  setKind("sync");
                  start.mutate({ p: s(r.provider), a: "sync" });
                }}
              >
                Synchronize
              </button>
            </div>
          </div>
        ))}
      </div>
      {error && <p className="form-error">{error}</p>}
      {job && (
        <section className="panel job-panel">
          <h2>{kind === "preview" ? "Preview impact" : "Synchronization"}</h2>
          <p>Collecting… Analysing… Ready when the job completes.</p>
          <Status v={jq.data?.status} />
          <p>{s(jq.data?.progress)}</p>
          {jq.data?.status === "SUCCEEDED" && jq.data?.result ? (
            kind === "preview" ? (
              <SourceImpact result={jq.data.result as Row} />
            ) : (
              <p>Synchronization completed for {s((jq.data.result as Row).provider)}.</p>
            )
          ) : null}
          {jq.data?.error ? <p className="form-error">{s(jq.data.error)}</p> : null}
          {jq.isError && <p className="form-error">{s(jq.error)}</p>}
        </section>
      )}
      {editing && (
        <Drawer title={editing.id ? "Configure source" : "Add source"} close={() => setEditing(null)}>
          <form
            className="admin-form"
            onSubmit={(e) => {
              e.preventDefault();
              save.mutate(editing);
            }}
          >
            <h4>SOURCE</h4>
            <label>
              Provider name
              <input
                required
                pattern="[a-z0-9-]+"
                disabled={Boolean(editing.id)}
                value={s(editing.provider, "")}
                onChange={(e) => update("provider", e.target.value)}
              />
            </label>
            <label>
              Type
              <select value={s(editing.type)} onChange={(e) => update("type", e.target.value)}>
                <option value="active_directory">Active Directory</option>
                <option value="openldap">OpenLDAP</option>
              </select>
            </label>
            <h4>CONNECTION</h4>
            {editing.type === "active_directory" ? (
              <label>
                Server
                <input
                  required
                  value={s((editing.connection as Row | undefined)?.server, "")}
                  onChange={(e) => updateNested("connection", "server", e.target.value)}
                />
              </label>
            ) : (
              <>
                <label>
                  LDAP URI
                  <input
                    required
                    value={s((editing.connection as Row | undefined)?.uri, "")}
                    onChange={(e) => updateNested("connection", "uri", e.target.value)}
                  />
                </label>
                <label>
                  Base DN
                  <input
                    required
                    value={s((editing.connection as Row | undefined)?.base_dn, "")}
                    onChange={(e) => updateNested("connection", "base_dn", e.target.value)}
                  />
                </label>
                <label>
                  Bind DN
                  <input
                    value={s((editing.connection as Row | undefined)?.bind_dn, "")}
                    onChange={(e) => updateNested("connection", "bind_dn", e.target.value)}
                  />
                </label>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={(editing.collection as Row | undefined)?.allow_anonymous === true}
                    onChange={(e) => updateNested("collection", "allow_anonymous", e.target.checked)}
                  />
                  Allow anonymous LDAP export
                </label>
                <p className="field-note">Only enable this when the directory intentionally permits anonymous read access. Authenticated collection should use LDAPS or StartTLS.</p>
              </>
            )}
            {supportsAttributeMapping ? <>
              <h4>BUSINESS MAPPING</h4>
              <p className="field-note">Technical identifiers and group membership remain connector-controlled. Suggestions are bounded; safe custom attribute names can also be typed and are validated when saved.</p>
              {[
              ["Display name", "display_name"],
              ["Description", "description"],
              ["Application", "application"],
              ["Permission", "business_permission"],
              ["Resource", "resource"],
              ["Owner", "owner"],
              ].map(([label, field]) => {
              const entry = ((((editing.business_mapping ?? {}) as Row)[field] ?? { mode: "default" }) as Row);
              const mode = s(entry.mode, "default");
              return (
                <div className="mapping-row" key={field}>
                  <label>{label}
                    <select value={mode} onChange={(event) => updateMapping(field, "mode", event.target.value)}>
                      <option value="default">Default</option>
                      <option value="attribute">Source field</option>
                      <option value="static">Static value</option>
                      <option value="none">Not configured</option>
                    </select>
                  </label>
                  {mode === "attribute" ? (
                    <label>Source field
                      <input list="safe-source-fields" value={s(entry.attribute, "")} onChange={(event) => updateMapping(field, "attribute", event.target.value)} />
                    </label>
                  ) : mode === "static" ? (
                    <label>Static value<input value={s(entry.value, "")} onChange={(event) => updateMapping(field, "value", event.target.value)} /></label>
                  ) : null}
                </div>
              );
              })}
              <datalist id="safe-source-fields">
                {Object.entries((sourceFields.data?.attributes ?? {}) as Row).filter(([, info]) => (info as Row).mappable !== false).map(([name]) => <option value={name} key={name} />)}
              </datalist>
            </> : null}
            <h4>SECRET REFERENCES</h4>
            <label>
              Username environment variable
              <input
                placeholder="LDAP_USERNAME"
                value={s((editing.credentials as Row | undefined)?.username_env, "")}
                onChange={(e) => updateNested("credentials", "username_env", e.target.value || undefined)}
              />
            </label>
            <label>
              Password environment variable
              <input
                placeholder="LDAP_PASSWORD"
                value={s((editing.credentials as Row | undefined)?.password_env, "")}
                onChange={(e) => updateNested("credentials", "password_env", e.target.value || undefined)}
              />
            </label>
            {testResult ? (
              <section className="mapping-diagnostics">
                <p className="form-success">Connection: {s((testResult.connection as Row | undefined)?.status, "success")}</p>
                {arr((testResult.mapping as Row | undefined)?.diagnostics).map((row) => (
                  <p key={s(row.field)}><strong>{s(row.field).replaceAll("_", " ")}</strong> · {s(row.attribute, s(row.mode))} · {row.coverage === undefined ? "—" : `${s(row.coverage)}% populated in sample`} · <Status v={row.status} /></p>
                ))}
              </section>
            ) : null}
            <div className="button-row">
              <button
                type="button"
                className="button subtle"
                disabled={test.isPending}
                onClick={() => test.mutate(editing)}
              >
                Test connection
              </button>
              <button type="submit" className="button primary" disabled={save.isPending}>
                Save
              </button>
            </div>
          </form>
        </Drawer>
      )}
    </>
  );
}
function AuditTrail() {
  const [page, setPage] = useState(0),
    limit = 25,
    q = useQuery({
      queryKey: ["audit-events", page],
      queryFn: () => getPage("audit-events", { limit, offset: page * limit }),
    });
  return (
    <>
      <Head title="Audit trail" />
      <p className="muted">Immutable trace of sensitive EARE governance operations.</p>
      <Table
        cols={["When", "Actor", "Event", "Object", "Details"]}
        q={q}
        rows={arr(q.data?.items).map((r) => [
          when(r.created_at),
          s(r.actor),
          s(r.event_type),
          s(r.object_type) + " / " + s(r.object_id),
          readableDetails(r.details),
        ])}
      />
      <Pager
        total={q.data?.total ?? 0}
        limit={limit}
        offset={page * limit}
        setOffset={(n) => setPage(Math.max(0, Math.floor(n / limit)))}
        setLimit={() => {}}
      />
    </>
  );
}
function Reports() {
  const campaignsQuery = useQuery({
      queryKey: ["reports"],
      queryFn: () => getPage("campaigns", { limit: 100 }),
    }),
    campaigns = arr(campaignsQuery.data?.items),
    [chosen, setChosen] = useState(() => new URLSearchParams(window.location.search).get("campaign") ?? ""),
    [showPreview, setShowPreview] = useState(true),
    // Reports are read after a campaign is closed: offer that one first.
    selected =
      campaigns.find((r) => s(r.id) === chosen) ??
      campaigns.find((r) => s(r.status) === "closed") ??
      campaigns[0],
    id = s(selected?.id, ""),
    [search, setSearch] = useState(""),
    debounced = debounce(search),
    [classification, setClassification] = useState(""),
    [decision, setDecision] = useState(""),
    [provider, setProvider] = useState(""),
    [owner, setOwner] = useState(""),
    [offset, setOffset] = useState(0),
    [limit, setLimit] = useState(25),
    [sort, setSort] = useState(""),
    [order, setOrder] = useState("asc"),
    columns = useColumnFilters(),
    sorting: SortState = {
      sort,
      order,
      toggle: (field: string) => {
        setOrder(sort === field && order === "asc" ? "desc" : "asc");
        setSort(field);
        setOffset(0);
      },
    },
    q = useQuery({
      queryKey: [
        "report",
        id,
        debounced,
        classification,
        decision,
        provider,
        owner,
        limit,
        offset,
        sort,
        order,
        columns.key,
      ],
      queryFn: () =>
        getJson(`reports/${encodeURIComponent(id)}/results`, {
          search: debounced,
          classification,
          decision,
          provider,
          owner,
          limit,
          offset,
          sort,
          order,
          ...columns.params,
        }),
      enabled: Boolean(id),
    }),
    remediationQuery = useQuery({
      queryKey: ["report-remediation", id],
      queryFn: () => getPage("remediation-actions", { campaign: id, limit: 100 }),
      enabled: Boolean(id),
    }),
    summary = (q.data?.summary ?? {}) as Row,
    facets = (q.data?.facets ?? {}) as Row,
    rows = arr(q.data?.items),
    remediationActions = arr(remediationQuery.data?.items),
    campaign = (q.data?.campaign ?? {}) as Row;
  useEffect(() => setOffset(0), [debounced, classification, decision, provider, owner, id]);
  if (!campaigns.length)
    return (
      <>
        <Head title="Reports" />
        <div className="table-wrap">
          <div className="empty">
            <strong>{uiLabel("No campaign yet")}</strong>
            <span>{ui("ui.reportExplain", { defaultValue: "A report describes what a campaign decided. Run one first." })}</span>
            <NavLink className="button subtle" to="/campaigns/new">
              {uiLabel("Create a campaign")}
            </NavLink>
          </div>
        </div>
      </>
    );
  return (
    <>
      <Head title="Reports">
        <div className="button-row">
          <button className="button primary" type="button" onClick={() => setShowPreview((value) => !value)}>
            {showPreview ? uiLabel("Hide report") : uiLabel("View report")}
          </button>
          <a className="button subtle" href={`/api/reports/${id}/html`}>
            {uiLabel("Download HTML")}
          </a>
          <a className="button subtle" href={`/api/reports/${id}/csv`}>
            {uiLabel("Download CSV")}
          </a>
          <a className="button subtle" href={`/api/reports/${id}/json`}>
            {uiLabel("Download JSON")}
          </a>
          <a className="button subtle" href={`/api/reports/${id}/pdf`}>
            {uiLabel("Download PDF")}
          </a>
        </div>
      </Head>
      <div className="filterbar">
        <select className="filter-button" value={id} onChange={(e) => setChosen(e.target.value)}>
          {campaigns.map((r) => (
            <option key={s(r.id)} value={s(r.id)}>
              {s(r.name)} — {s(r.status)}
            </option>
          ))}
        </select>
        <Status v={campaign.status ?? selected?.status} />
        <span className="muted">
          {campaign.closed_at
            ? `closed ${when(campaign.closed_at)}`
            : campaign.opened_at
              ? `opened ${when(campaign.opened_at)}`
              : "not opened yet"}
        </span>
      </div>
      {showPreview ? <section className="report-workspace">
        <div className="report-workspace-head">
          <div>
            <span className="eyebrow">{uiLabel("Governance evidence")}</span>
            <h2>{uiLabel("Final campaign report")}</h2>
            <p className="muted">{ui("ui.reportDisplayed", { defaultValue: "The report is displayed here as a complete document. Use the downloads above to distribute it." })}</p>
          </div>
          <a className="button subtle" href={`/api/reports/${id}/html?inline=true`} target="_blank" rel="noreferrer">
            {uiLabel("Open full report")}
          </a>
        </div>
        <section className="remediation-focus" aria-labelledby="remediation-focus-title">
          <div className="remediation-focus-head">
            <div>
              <span className="eyebrow">{uiLabel("Operational follow-up")}</span>
              <h2 id="remediation-focus-title">{uiLabel("Actions to implement")}</h2>
              <p>{ui("ui.remediationReadonly", { defaultValue: "These are instructions for administrators. EARE does not change AD, LDAP, cloud or application providers." })}</p>
            </div>
            <div className="remediation-count">
              <strong>{remediationActions.length}</strong>
              <span>{ui("ui.actionCount", { count: remediationActions.length })}</span>
            </div>
          </div>
          {remediationActions.length ? <>
            <div className="remediation-summary">
              {(["revoke", "grant", "pending", "exported"] as const).map((key) => {
                const value = key === "pending" || key === "exported"
                  ? remediationActions.filter((item) => s(item.status, "pending") === key).length
                  : remediationActions.filter((item) => s(item.action, "").toLowerCase() === key).length;
                return <div key={key}><strong>{value}</strong><span>{key === "revoke" ? "to remove" : key === "grant" ? "to grant" : key}</span></div>;
              })}
            </div>
            <div className="remediation-table-wrap">
              <table className="remediation-table">
                <thead><tr><th>Action</th><th>Account</th><th>Source</th><th>Access / role</th><th>Permission</th><th>Reason</th><th>Status</th></tr></thead>
                <tbody>{remediationActions.slice(0, 12).map((item) => {
                  const context = item.business_context;
                  const application = contextValue(context, "application", "source");
                  return <tr key={s(item.id, `${s(item.identity_identifier)}-${s(item.access_name)}`)}>
                    <td><span className={`action-pill ${s(item.action, "").toLowerCase()}`}>{s(item.action, s(item.decision, "—"))}</span></td>
                    <td><strong>{s(item.identity_display_name, s(item.identity_identifier))}</strong><small>{s(item.identity_provider)}</small></td>
                    <td>{s(item.access_provider)}</td>
                    <td><strong>{s(item.access_display_name, s(item.access_name))}</strong><small>{application || targetText(item.target)}</small></td>
                    <td>{s(item.permission, s(item.technical_permission, "—"))}</td>
                    <td>{s(item.comment, "Decision requires operational change")}</td>
                    <td><Status v={item.status ?? "pending"} /></td>
                  </tr>;
                })}</tbody>
              </table>
              {remediationActions.length > 12 ? <p className="remediation-more">Showing 12 of {remediationActions.length}. <NavLink to={`/actions?campaign=${encodeURIComponent(id)}`}>View all actions</NavLink></p> : null}
            </div>
          </> : <div className="remediation-empty"><Check size={18} /> No remediation action was generated for this campaign.</div>}
        </section>
        <iframe className="report-document" title={`Final report for ${s(campaign.name)}`} src={`/api/reports/${id}/html?inline=true`} loading="lazy" />
      </section> : null}
      <div className="metrics">
        {[
          ["Reviewed accesses", q.data?.total, "in this campaign"],
          ["Approved", summary.approve, "kept as is"],
          ["Revoked", summary.revoke, "to be removed"],
          ["Still pending", summary.pending, "no decision yet"],
        ].map(([label, value, hint]) => (
          <div className="metric" key={String(label)}>
            <div className="metric-label">{String(label)}</div>
            <strong>{s(value, "0")}</strong>
            <small>{String(hint)}</small>
          </div>
        ))}
      </div>
      <section className="panel">
        <div className="panel-title">
          <h2>What the campaign found</h2>
          <span className="muted">
            {s(summary.identities, "0")} identities · {s(summary.providers, "0")} source(s)
          </span>
        </div>
        <div className="diff-summary">
          <strong>{s(summary.expected_and_observed, "0")} as expected</strong>
          <strong>{s(summary.unexpected, "0")} not expected</strong>
          <strong>{s(summary.missing, "0")} missing</strong>
          <strong>{s(summary.disabled_with_access, "0")} disabled accounts with access</strong>
          <strong>{s(summary.technical_account_without_owner, "0")} technical accounts without owner</strong>
        </div>
      </section>
      <Filter v={search} onChange={setSearch}>
        <SelectFilter
          value={classification}
          onChange={setClassification}
          options={vals(facets.classification)}
          placeholder="Classification"
        />
        <SelectFilter
          value={decision}
          onChange={setDecision}
          options={vals(facets.decision)}
          placeholder="Decision"
        />
        <SelectFilter
          value={provider}
          onChange={setProvider}
          options={vals(facets.provider)}
          placeholder="Source"
        />
        <SelectFilter value={owner} onChange={setOwner} options={vals(facets.owner)} placeholder="Reviewer" />
      </Filter>
      <Table
        cols={["Identity", "Access", "Application", "Permission", "State", "Decision", "Reason", "Reviewer"]}
        fields={[
          "identity",
          "access",
          "service",
          "permission",
          "classification",
          "decision",
          "comment",
          "reviewer",
        ]}
        sorting={sorting}
        filtering={columns.filtering}
        q={q}
        rows={rows.map((r) => [
          <>
            {s(r.identity)}
            <Sub>{s(r.identity_status, "")}</Sub>
          </>,
          <>
            {s(r.access)}
            <Sub>{s(r.description, "")}</Sub>
          </>,
          s(r.service),
          s(r.permission),
          <>
            <Status v={r.classification} />
            <Sub>{s(r.findings, "")}</Sub>
          </>,
          <Status v={r.decision} />,
          s(r.comment, ""),
          s(r.reviewer),
        ])}
      />
      <Pager
        total={Number(q.data?.total ?? 0)}
        limit={limit}
        offset={offset}
        setOffset={setOffset}
        setLimit={setLimit}
      />
    </>
  );
}
const LOCAL_SOURCE = "local";
const blankUser = (source = LOCAL_SOURCE): Row => ({
  username: "",
  display_name: "",
  role: "OPERATOR",
  scopes: [],
  password: "",
  enabled: true,
  api_access_enabled: false,
  auth_source: source,
});
function Confirm({
  title,
  intro,
  confirmLabel,
  danger,
  pending,
  error,
  disabled,
  cancel,
  confirm,
  children,
}: {
  title: string;
  intro: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  pending?: boolean;
  error?: string;
  disabled?: boolean;
  cancel: () => void;
  confirm: () => void;
  children?: ReactNode;
}) {
  return (
    <div className="modal-backdrop" onClick={cancel}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>{title}</h2>
        {intro}
        {children}
        {error && <p className="form-error">{error}</p>}
        <div className="modal-actions">
          <button className="button subtle" onClick={cancel}>
            Cancel
          </button>
          <button
            className={danger ? "button danger" : "button primary"}
            disabled={pending || disabled}
            onClick={confirm}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
function UsersPage() {
  const c = useQueryClient(),
    q = useQuery({ queryKey: ["system"], queryFn: () => getJson("system") }),
    [search, setSearch] = useState(""),
    [open, setOpen] = useState(false),
    [picking, setPicking] = useState<Row | null>(null),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [confirming, setConfirming] = useState<{ action: string; user: Row } | null>(null),
    [newPassword, setNewPassword] = useState(""),
    [reassignTo, setReassignTo] = useState(""),
    [form, setForm] = useState<Row>(blankUser()),
    directories = arr(q.data?.identity_providers).filter((r) => r.enabled && s(r.kind) === "LDAP"),
    configuredProviders = arr(q.data?.providers),
    source = s(form.auth_source, LOCAL_SOURCE),
    fromDirectory = source !== LOCAL_SOURCE,
    m = useMutation({
      mutationFn: () => {
        const scopes = vals(form.scopes);
        const password = String(form.password || "");
        return postJson("system/users", {
          ...form,
          scopes,
          // A directory account keeps no password, and an empty field must leave a pending
          // password change untouched.
          password: fromDirectory || !password ? undefined : password,
          ...(password && !fromDirectory ? { must_change_password: true } : {}),
        });
      },
      onSuccess: async (d) => {
        setOpen(false);
        setError("");
        setNotice(`${s(d.display_name, s(d.username))} saved`);
        await c.invalidateQueries({ queryKey: ["system"] });
      },
      onError: (e) => setError(s(e, "Unable to save user")),
    }),
    globalApi = useMutation({
      mutationFn: (enabled: boolean) => putJson("system/settings/external-user-api", { enabled }),
      onSuccess: async (d) => {
        setError("");
        setNotice(`External user API ${d.external_user_api_enabled ? "enabled" : "disabled"}`);
        await c.invalidateQueries({ queryKey: ["system"] });
      },
      onError: (e) => setError(s(e, "Unable to update external API setting")),
    }),
    lifecycle = useMutation({
      mutationFn: ({ action, user }: { action: string; user: Row }) =>
        postJson(
          `system/users/${encodeURIComponent(s(user.username))}/${action}`,
          action === "reset-password" ? { password: newPassword } : undefined,
        ),
      onSuccess: async (_d, variables) => {
        const name = s(variables.user.display_name, s(variables.user.username));
        setConfirming(null);
        setNewPassword("");
        setError("");
        setNotice(
          variables.action === "disable"
            ? `${name} can no longer sign in`
            : variables.action === "enable"
              ? `${name} can sign in again`
              : variables.action === "api-token/revoke"
                ? `${name}'s API key was revoked`
                : `New password set for ${name}. They must change it at their next sign-in.`,
        );
        await c.invalidateQueries({ queryKey: ["system"] });
      },
      onError: (e) => setError(s(e, "Operation failed")),
    }),
    reassign = useMutation({
      mutationFn: (user: Row) =>
        postJson(`system/users/${encodeURIComponent(s(user.username))}/reassign-reviews`, {
          to: reassignTo,
        }),
      onSuccess: async (d) => {
        setConfirming(null);
        setReassignTo("");
        setError("");
        setNotice(`${s(d.review_items, "0")} pending review(s) moved to ${s(d.to)}`);
        await c.invalidateQueries({ queryKey: ["system"] });
      },
      onError: (e) => setError(s(e, "Unable to reassign the reviews")),
    }),
    users = arr(q.data?.users).filter(
      (r) =>
        !search ||
        [r.username, r.display_name, r.role, r.auth_source]
          .map(String)
          .join(" ")
          .toLowerCase()
          .includes(search.toLowerCase()),
    );
  const edit = (r?: Row) => {
    setError("");
    setForm(r ? { ...r, scopes: vals(r.scopes), password: "" } : blankUser());
    setOpen(true);
  };
  const confirmUserAction = (action: string, user: Row) => {
    setError("");
    setNotice("");
    setNewPassword("");
    setReassignTo("");
    setConfirming({ action, user });
  };
  const importAccount = (directory: Row, account: Row) => {
    setError("");
    setForm({
      ...blankUser(s(directory.name)),
      username: s(account.login),
      display_name: s(account.display_name, s(account.login)),
      external_id: s(account.dn),
    });
    setPicking(null);
    setOpen(true);
  };
  return (
    <>
      <Head title="Users & permissions">
        <div className="button-row">
          <Status v={q.data?.external_user_api_enabled ? "enabled" : "disabled"} />
          <button className="button subtle" onClick={() => globalApi.mutate(!q.data?.external_user_api_enabled)} disabled={globalApi.isPending}>
            {q.data?.external_user_api_enabled ? "Disable external user API" : "Enable external user API"}
          </button>
          {directories.map((d) => (
            <button className="button subtle" key={s(d.id)} onClick={() => setPicking(d)}>
              + From {s(d.name)}
            </button>
          ))}
          <button className="button primary" onClick={() => edit()}>
            + New local user
          </button>
        </div>
      </Head>
      {!directories.length && (
        <p className="muted">
          Only local accounts can sign in today. Configure a directory in Authentication to import accounts
          from it.
        </p>
      )}
      {notice && <p className="muted">{notice}</p>}
      {error && !open && !confirming && <p className="form-error">{error}</p>}
      <Filter v={search} onChange={setSearch} />
      <Table
        cols={["User", "Username", "Signs in with", "Role", "Authorized domains", "API access", "Pending reviews", "Status", "Actions"]}
        q={q}
        rows={users.map((r) => [
          s(r.display_name),
          s(r.username),
          s(r.auth_source, LOCAL_SOURCE) === LOCAL_SOURCE ? "Local account" : s(r.auth_source),
          <Status v={r.role} />,
          s(r.role) === "ADMIN" ? "All domains" : s(r.role) === "GROUP_OWNER" ? "Assigned reviews" : s(vals(r.scopes).join(", "), "None"),
          <div>
            <Status v={r.api_access_enabled ? "enabled" : "disabled"} />
            {r.api_token_active ? <small className="field-note">{s(r.api_token_prefix)} · last used {s(r.api_token_last_used_at, "never")}</small> : null}
          </div>,
          Number(r.pending_reviews) > 0 ? s(r.pending_reviews) : "—",
          <>
            <Status v={r.enabled ? "enabled" : "disabled"} />
            {r.must_change_password ? <span className="muted"> · password change required</span> : null}
          </>,
          <div className="row-actions">
            <button className="link-button" onClick={() => edit(r)}>
              Edit
            </button>
            <ActionMenu
              label={`More actions for ${s(r.display_name, s(r.username))}`}
              actions={[
                ...(s(r.auth_source, LOCAL_SOURCE) === LOCAL_SOURCE
                  ? [{ label: "Reset password", onClick: () => confirmUserAction("reset-password", r) }]
                  : []),
                ...(r.api_token_active
                  ? [{ label: "Revoke API key", danger: true, onClick: () => confirmUserAction("api-token/revoke", r) }]
                  : []),
                ...(Number(r.pending_reviews) > 0
                  ? [{ label: "Reassign reviews", onClick: () => confirmUserAction("reassign", r) }]
                  : []),
                {
                  label: r.enabled ? "Disable" : "Enable",
                  danger: Boolean(r.enabled),
                  onClick: () => confirmUserAction(r.enabled ? "disable" : "enable", r),
                },
              ]}
            />
          </div>,
        ])}
      />
      {confirming && confirming.action === "disable" && (
        <Confirm
          title={`Disable ${s(confirming.user.display_name, s(confirming.user.username))}?`}
          intro={
            <>
              <p>This person can no longer sign in, and any open session stops working immediately.</p>
              {Number(confirming.user.pending_reviews) > 0 && (
                <p className="form-error">
                  {s(confirming.user.pending_reviews)} review(s) are still waiting on this person. Hand them
                  over first with <strong>Reassign reviews</strong>, otherwise their campaign cannot be
                  closed.
                </p>
              )}
              <p className="muted">
                Their past decisions, their assigned reviews and the audit trail are kept. You can enable the
                account again at any time.
              </p>
            </>
          }
          confirmLabel="Disable account"
          danger
          pending={lifecycle.isPending}
          error={error}
          cancel={() => setConfirming(null)}
          confirm={() => lifecycle.mutate(confirming)}
        />
      )}
      {confirming && confirming.action === "enable" && (
        <Confirm
          title={`Enable ${s(confirming.user.display_name, s(confirming.user.username))}?`}
          intro={<p>This person can sign in again with their existing credentials.</p>}
          confirmLabel="Enable account"
          pending={lifecycle.isPending}
          error={error}
          cancel={() => setConfirming(null)}
          confirm={() => lifecycle.mutate(confirming)}
        />
      )}
      {confirming && confirming.action === "reassign" && (
        <Confirm
          title={`Reassign the reviews of ${s(confirming.user.display_name, s(confirming.user.username))}?`}
          intro={
            <p>
              {s(confirming.user.pending_reviews)} review(s) waiting in open campaigns move to someone else.
              Decisions already taken keep their author.
            </p>
          }
          confirmLabel="Reassign reviews"
          pending={reassign.isPending}
          disabled={!reassignTo}
          error={error}
          cancel={() => setConfirming(null)}
          confirm={() => reassign.mutate(confirming.user)}
        >
          <label>
            Hand the reviews to
            <select value={reassignTo} onChange={(e) => setReassignTo(e.target.value)}>
              <option value="">Select a user</option>
              {users
                .filter((u) => u.enabled && s(u.username) !== s(confirming.user.username))
                .map((u) => (
                  <option key={s(u.username)} value={s(u.username)}>
                    {s(u.display_name, s(u.username))} · {s(u.role)}
                  </option>
                ))}
            </select>
          </label>
        </Confirm>
      )}
      {confirming && confirming.action === "api-token/revoke" && (
        <Confirm
          title={`Revoke ${s(confirming.user.display_name, s(confirming.user.username))}'s API key?`}
          intro={<p>The key stops working immediately. The user can generate a new key if API access remains enabled.</p>}
          confirmLabel="Revoke API key"
          danger
          pending={lifecycle.isPending}
          error={error}
          cancel={() => setConfirming(null)}
          confirm={() => lifecycle.mutate(confirming)}
        />
      )}
      {confirming && confirming.action === "reset-password" && (
        <Confirm
          title={`Reset the password of ${s(confirming.user.display_name, s(confirming.user.username))}?`}
          intro={
            <p className="muted">
              Give them this password through a channel they trust. EARE asks them to choose a new one at
              their next sign-in.
            </p>
          }
          confirmLabel="Reset password"
          pending={lifecycle.isPending}
          disabled={newPassword.length < 12}
          error={error}
          cancel={() => setConfirming(null)}
          confirm={() => lifecycle.mutate(confirming)}
        >
          <label>
            New password (12 characters minimum)
            <input
              autoFocus
              type="password"
              minLength={12}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
          </label>
        </Confirm>
      )}
      {picking && (
        <DirectoryPicker
          directory={picking}
          close={() => setPicking(null)}
          pick={(account) => importAccount(picking, account)}
        />
      )}
      {open && (
        <Drawer
          size="wide"
          title={form.id ? "Edit user" : fromDirectory ? "Import user" : "New local user"}
          close={() => setOpen(false)}
        >
          <form
            className="drawer-form"
            onSubmit={(e) => {
              e.preventDefault();
              m.mutate();
            }}
          >
            <h4>ACCOUNT</h4>
            <label>
              {ui("auth.username")}
              <input
                required
                disabled={Boolean(form.id) || fromDirectory}
                value={s(form.username, "")}
                onChange={(e) => setForm({ ...form, username: e.target.value })}
              />
            </label>
            <label>
              Display name
              <input
                required
                value={s(form.display_name, "")}
                onChange={(e) => setForm({ ...form, display_name: e.target.value })}
              />
            </label>
            <h4>PERMISSIONS</h4>
            <label>
              Role
              <select value={s(form.role)} onChange={(e) => setForm({ ...form, role: e.target.value, ...(e.target.value === "ADMIN" ? { scopes: ["*"] } : e.target.value === "GROUP_OWNER" ? { scopes: [] } : { scopes: vals(form.scopes).filter((scope) => scope !== "*") }) })}>
                <option>ADMIN</option>
                <option>OPERATOR</option>
                <option>GROUP_OWNER</option>
                <option>BUSINESS_ADMIN</option>
                <option>REMEDIATION_MANAGER</option>
              </select>
            </label>
            <p className="field-note">{roleHelp(s(form.role))}</p>
            {s(form.role) === "ADMIN" ? (
              <p className="field-note">Administrators have global access to all domains.</p>
            ) : s(form.role) === "GROUP_OWNER" ? (
              <p className="field-note">Group Owners do not need provider scopes; they see only explicitly assigned ReviewItems.</p>
            ) : (
              <label>
                Authorized domains
                <select
                  multiple
                  size={Math.min(6, Math.max(2, configuredProviders.length))}
                  value={vals(form.scopes)}
                  onChange={(event) => setForm({ ...form, scopes: Array.from(event.currentTarget.selectedOptions, (option) => option.value) })}
                >
                  {configuredProviders.map((provider) => (
                    <option key={s(provider.name)} value={s(provider.name)}>{providerLabel(provider)}</option>
                  ))}
                </select>
                <span className="field-note">Select every provider where this role may act. A campaign spanning any other provider will be wholly unavailable.</span>
              </label>
            )}
            {s(form.role) === "GROUP_OWNER" && (
              <p className="field-note">
                The username must match the reviewer identifier in the audited source, otherwise no review is
                assigned to this person.
              </p>
            )}
            <h4>AUTHENTICATION</h4>
            {fromDirectory ? (
              <>
                <p>
                  Signs in with <strong>{source}</strong>. EARE stores no password for this account.
                </p>
                <p className="muted">{s(form.external_id)}</p>
              </>
            ) : (
              <label>
                {form.id ? "Set new password" : "Password"}
                <input
                  required={!form.id}
                  minLength={12}
                  type="password"
                  placeholder={form.id ? "Leave empty to keep the current password" : ""}
                  value={s(form.password, "")}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                />
              </label>
            )}
            <h4>EXTERNAL USER API</h4>
            <label className="check-row">
              <input
                type="checkbox"
                checked={Boolean(form.api_access_enabled)}
                onChange={(e) => setForm({ ...form, api_access_enabled: e.target.checked })}
              />
              Allow this account to use the external read-only API
            </label>
            <p className="field-note">Disabling API access revokes existing API keys. The user must generate a new key after re-enablement.</p>
            <h4>STATUS</h4>
            {form.id ? (
              <div className="status-row">
                <Status v={form.enabled ? "enabled" : "disabled"} />
                <button
                  type="button"
                  className="button subtle"
                  onClick={() => {
                    setOpen(false);
                    setError("");
                    setNotice("");
                    setConfirming({ action: form.enabled ? "disable" : "enable", user: form });
                  }}
                >
                  {form.enabled ? "Disable account" : "Enable account"}
                </button>
              </div>
            ) : (
              <p className="field-note">
                The account is active as soon as it is created. You can disable it at any time from the user
                list.
              </p>
            )}
            {error && <p className="form-error">{error}</p>}
            <button className="button primary" type="submit" disabled={m.isPending}>
              {form.id ? "Save user" : fromDirectory ? "Import user" : "Create user"}
            </button>
          </form>
        </Drawer>
      )}
    </>
  );
}
function roleHelp(role: string) {
  if (role === "ADMIN") return "Configures EARE, manages users, and can run every governance operation.";
  if (role === "OPERATOR")
    return "Manages campaigns only when every provider/domain exposed by the campaign is authorized.";
  if (role === "GROUP_OWNER") return "Only sees and decides the reviews assigned to this person.";
  if (role === "REMEDIATION_MANAGER") return "Tracks remediation work for the authorized source domains and records completion evidence.";
  return "Only sees the remediation actions of the authorized domains selected for this account.";
}
function DirectoryPicker({
  directory,
  close,
  pick,
}: {
  directory: Row;
  close: () => void;
  pick: (account: Row) => void;
}) {
  const [search, setSearch] = useState(""),
    selected = debounce(search),
    q = useQuery({
      queryKey: ["directory-accounts", s(directory.name), selected],
      queryFn: () =>
        getJson(`system/identity-providers/${encodeURIComponent(s(directory.name))}/accounts`, {
          search: selected,
          limit: 25,
        }),
    }),
    accounts = arr(q.data?.items);
  return (
    <Drawer title={`Import from ${s(directory.name)}`} close={close}>
      <p className="muted">
        Imported people sign in with their directory password. Their role and scopes are managed here.
      </p>
      <Filter v={search} onChange={setSearch} />
      <Table
        cols={["Person", "Login", "Email", ""]}
        q={q}
        rows={accounts.map((r) => [
          s(r.display_name),
          s(r.login),
          s(r.email),
          r.imported ? (
            <span className="muted">Already imported</span>
          ) : (
            <button className="link-button" onClick={() => pick(r)}>
              Import
            </button>
          ),
        ])}
      />
    </Drawer>
  );
}
const blankDirectory = (): Row => ({
  name: "",
  kind: "LDAP",
  endpoint: "ldaps://",
  enabled: true,
  settings: { base_dn: "", login_attribute: "uid", bind_dn: "", bind_password_env: "" },
});
function Auth() {
  const c = useQueryClient(),
    q = useQuery({ queryKey: ["system"], queryFn: () => getJson("system") }),
    [editing, setEditing] = useState<Row | null>(null),
    [notice, setNotice] = useState<{ tone: string; text: string } | null>(null),
    directories = arr(q.data?.identity_providers),
    localCount = arr(q.data?.users).filter((r) => s(r.auth_source, LOCAL_SOURCE) === LOCAL_SOURCE).length,
    settings = (editing?.settings as Row | undefined) || {},
    updateSettings = (key: string, value: unknown) =>
      setEditing((x) => (x ? { ...x, settings: { ...((x.settings as Row) || {}), [key]: value } } : x)),
    test = useMutation({
      mutationFn: (body: Row) => postJson("system/identity-providers/test", body),
      onSuccess: (d) => setNotice({ tone: "ok", text: s(d.message, "Connection test succeeded") }),
      onError: (e) => setNotice({ tone: "error", text: s(e, "Connection test failed") }),
    }),
    save = useMutation({
      mutationFn: (body: Row) => postJson("system/identity-providers", body),
      onSuccess: async (d) => {
        setEditing(null);
        setNotice({ tone: "ok", text: `Directory "${s(d.name)}" saved` });
        await c.invalidateQueries({ queryKey: ["system"] });
      },
      onError: (e) => setNotice({ tone: "error", text: s(e, "Unable to save the directory") }),
    });
  return (
    <>
      <Head title="Authentication">
        <button
          className="button primary"
          onClick={() => {
            setNotice(null);
            setEditing(blankDirectory());
          }}
        >
          + Add LDAP directory
        </button>
      </Head>
      <p className="muted">
        How people sign in to EARE. The directories EARE audits are configured in Sources &amp; IdPs.
      </p>
      {notice && <p className={notice.tone === "ok" ? "form-success" : "form-error"}>{notice.text}</p>}
      <section className="panel">
        <h2>Local accounts</h2>
        <Status v="ACTIVE" />
        <p>
          {localCount} local account(s). Passwords need at least 12 characters, a password set by an
          administrator must be changed at the next sign-in, and a session lasts 8 hours.
        </p>
        <NavLink className="button subtle" to="/system/users">
          Manage users
        </NavLink>
      </section>
      {directories.map((r) => (
        <section className="panel" key={s(r.id)}>
          <h2>{s(r.name)}</h2>
          <Status v={r.enabled ? "ACTIVE" : "DISABLED"} />
          <p>
            {s(r.kind)} · {s(r.endpoint)}
          </p>
          <p className="muted">
            Base DN: {s((r.settings as Row | undefined)?.base_dn)} · Login attribute:{" "}
            {s((r.settings as Row | undefined)?.login_attribute, "uid")}
          </p>
          <div className="button-row">
            <button
              className="button subtle"
              disabled={test.isPending}
              onClick={() => {
                setNotice(null);
                test.mutate(r);
              }}
            >
              Test connection
            </button>
            <button
              className="button subtle"
              onClick={() => {
                setNotice(null);
                setEditing(JSON.parse(JSON.stringify(r)));
              }}
            >
              Configure
            </button>
          </div>
        </section>
      ))}
      <section className="panel">
        <h2>Single sign-on (OIDC / SAML)</h2>
        <Status v="NOT_YET_ACTIVE" />
        <p>Not available yet. People sign in with a local account or with a configured LDAP directory.</p>
      </section>
      {editing && (
        <Drawer
          title={editing.id ? "Configure directory" : "Add LDAP directory"}
          close={() => setEditing(null)}
        >
          <form
            className="admin-form"
            onSubmit={(e) => {
              e.preventDefault();
              save.mutate(editing);
            }}
          >
            <h4>DIRECTORY</h4>
            <label>
              Name
              <input
                required
                disabled={Boolean(editing.id)}
                placeholder="corp-directory"
                value={s(editing.name, "")}
                onChange={(e) => setEditing({ ...editing, name: e.target.value })}
              />
            </label>
            <label>
              LDAP URI
              <input
                required
                placeholder="ldaps://ldap.example.org"
                value={s(editing.endpoint, "")}
                onChange={(e) => setEditing({ ...editing, endpoint: e.target.value })}
              />
            </label>
            <label>
              Base DN
              <input
                required
                placeholder="dc=example,dc=org"
                value={s(settings.base_dn, "")}
                onChange={(e) => updateSettings("base_dn", e.target.value)}
              />
            </label>
            <label>
              Login attribute
              <input
                placeholder="uid, or sAMAccountName on Active Directory"
                value={s(settings.login_attribute, "")}
                onChange={(e) => updateSettings("login_attribute", e.target.value)}
              />
            </label>
            <label>
              User filter
              <input
                placeholder="(objectClass=person)"
                value={s(settings.user_filter, "")}
                onChange={(e) => updateSettings("user_filter", e.target.value || undefined)}
              />
            </label>
            <h4>SERVICE ACCOUNT</h4>
            <p className="muted">
              Used to search the directory. Leave empty if the directory answers anonymous searches. People
              always sign in with their own credentials.
            </p>
            <label>
              Service account DN
              <input
                value={s(settings.bind_dn, "")}
                onChange={(e) => updateSettings("bind_dn", e.target.value)}
              />
            </label>
            <label>
              Password environment variable
              <input
                placeholder="EARE_DIRECTORY_PASSWORD"
                value={s(settings.bind_password_env, "")}
                onChange={(e) => updateSettings("bind_password_env", e.target.value)}
              />
            </label>
            <p className="muted">
              The password itself stays in the server environment and is never stored by the WebUI.
            </p>
            <label>
              <input
                type="checkbox"
                checked={Boolean(editing.enabled)}
                onChange={(e) => setEditing({ ...editing, enabled: e.target.checked })}
              />{" "}
              Allow people from this directory to sign in
            </label>
            {notice && <p className={notice.tone === "ok" ? "form-success" : "form-error"}>{notice.text}</p>}
            <div className="button-row">
              <button
                type="button"
                className="button subtle"
                disabled={test.isPending}
                onClick={() => {
                  setNotice(null);
                  test.mutate(editing);
                }}
              >
                Test connection
              </button>
              <button type="submit" className="button primary" disabled={save.isPending}>
                Save
              </button>
            </div>
          </form>
        </Drawer>
      )}
    </>
  );
}
export default App;
