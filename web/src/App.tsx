import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Navigate, NavLink, Route, Routes, useParams } from "react-router-dom";
import {
  AlertTriangle,
  Check,
  ChevronRight,
  Database,
  FileDown,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  Search,
  Settings,
  ShieldCheck,
  Users,
  X,
} from "lucide-react";
import {
  changePassword,
  getJson,
  getPage,
  getSession,
  login,
  logout,
  postDecision,
  postJson,
  type Principal,
  type Row,
} from "./api/client";
import { campaignCtas, currentStateLabels, pageCount, pageLabel, roleHome } from "./projections";
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
// The collectors store structured references; the WebUI must read them as a sentence.
const refText = (v: unknown): string => {
  if (typeof v === "string") return v;
  const row = (v ?? null) as Row | null;
  return row ? s(row.display_name, s(row.identifier, s(row.name, ""))) : "";
};
const permissionText = (v: unknown): string => refText(v);
const targetText = (v: unknown): string => {
  const target = (v ?? null) as Row | null;
  if (!target) return "";
  return [refText(target.resource), refText(target.component), refText(target.service)]
    .filter(Boolean)
    .join(" · ");
};
/** What this access lets someone do, in words: the collected description, or permission on target. */
const describeAccess = (row: Row): string => {
  const described = s(row.description, "");
  if (described) return described;
  const permission = permissionText(row.permission),
    target = targetText(row.target);
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
  const q = useQuery({ queryKey: ["session"], queryFn: getSession, retry: false });
  return q.isLoading ? (
    <div className="loading-page">Loading EARE…</div>
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
function PasswordChange() {
  const c = useQueryClient(),
    [p, setP] = useState(""),
    [confirm, setConfirm] = useState(""),
    [e, setE] = useState("");
  const m = useMutation({
    mutationFn: () => changePassword(p),
    onSuccess: (x) => c.setQueryData(["session"], x),
    onError: (x) => setE(s(x, "Unable to change password")),
  });
  return (
    <div className="login-page">
      <form
        className="login-card"
        onSubmit={(x) => {
          x.preventDefault();
          if (p !== confirm) {
            setE("Passwords do not match");
            return;
          }
          m.mutate();
        }}
      >
        <h1>Change your password</h1>
        <p>Set a new password before continuing.</p>
        <label>
          New password
          <input required minLength={12} type="password" value={p} onChange={(x) => setP(x.target.value)} />
        </label>
        <label>
          Confirm password
          <input
            required
            minLength={12}
            type="password"
            value={confirm}
            onChange={(x) => setConfirm(x.target.value)}
          />
        </label>
        {e && <p className="form-error">{e}</p>}
        <button className="button primary" disabled={m.isPending}>
          Change password
        </button>
      </form>
    </div>
  );
}
function Login() {
  const c = useQueryClient(),
    [u, setU] = useState(""),
    [p, setP] = useState(""),
    [visible, setVisible] = useState(false),
    [e, setE] = useState("");
  const m = useMutation({
    mutationFn: () => login(u, p),
    onSuccess: (x) => c.setQueryData(["session"], x),
    onError: (x) => setE(s(x, "Unable to sign in")),
  });
  return (
    <div className="login-page">
      <form
        className="login-card"
        onSubmit={(x) => {
          x.preventDefault();
          setE("");
          m.mutate();
        }}
      >
        <div className="login-brand">
          <span className="brand-mark">E</span>
          <div>
            <strong>EARE</strong>
            <span>Access review and certification</span>
          </div>
        </div>
        <h1>Sign in</h1>
        <label>
          Username
          <input
            required
            autoFocus
            autoComplete="username"
            value={u}
            onChange={(x) => setU(x.target.value)}
          />
        </label>
        <label>
          Password
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
              {visible ? "Hide" : "Show"}
            </button>
          </span>
        </label>
        {e && <p className="form-error">{e}</p>}
        <button className="button primary" disabled={m.isPending}>
          {m.isPending ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
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
      { to: "/actions", label: "Actions", icon: Check, roles: ["ADMIN", "OPERATOR", "BUSINESS_ADMIN"] },
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
  const [c, setC] = useState(false),
    q = useQueryClient();
  return (
    <div className="app-shell">
      <aside className={c ? "sidebar open" : "sidebar"}>
        <div className="brand">
          <span className="brand-mark">E</span>
          <span>EARE</span>
        </div>
        <nav>
          {navSections.map((section) => {
            const items = section.items.filter((x) => x.roles.includes(principal.role));
            return items.length ? (
              <div className="nav-section" key={section.heading ?? "product"}>
                {section.heading && <div className="nav-heading">{section.heading}</div>}
                {items.map(({ to, label, icon: I }) => (
                  <NavLink
                    key={to}
                    to={to}
                    end={to === "/"}
                    onClick={() => setC(false)}
                    className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
                  >
                    <I size={17} />
                    {label}
                  </NavLink>
                ))}
              </div>
            ) : null;
          })}
        </nav>
        <div className="sidebar-footer">
          <span className="health-dot" />
          API connected
        </div>
      </aside>
      <div className="page">
        <header className="topbar">
          <button className="icon-button mobile-menu" onClick={() => setC(!c)}>
            <Menu />
          </button>
          <span className="crumb">
            Workspace <ChevronRight size={14} /> Access governance
          </span>
          <div className="top-actions">
            <span className="user-name">
              {principal.display_name}
              <span>{principal.role}</span>
            </span>
            <button
              className="icon-button"
              aria-label="Sign out"
              onClick={async () => {
                await logout();
                q.removeQueries({ queryKey: ["session"] });
              }}
            >
              <LogOut />
            </button>
          </div>
        </header>
        <main>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/reviews" element={<Reviews />} />
            <Route path="/identities" element={<Identities />} />
            <Route path="/accesses" element={<Accesses />} />
            <Route path="/golden" element={<Golden />} />
            <Route path="/campaigns" element={<Campaigns />} />
            <Route path="/campaigns/new" element={<CampaignNew />} />
            <Route path="/campaigns/:id" element={<CampaignDetail />} />
            <Route path="/findings" element={<List path="findings" title="Findings" />} />
            <Route path="/actions" element={<List path="remediation-actions" title="Actions" />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/sources" element={<Sources />} />
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
function Head({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="page-header">
      <div>
        <div className="eyebrow">EARE</div>
        <h1>{title}</h1>
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
    label = STATUS_LABELS[raw] ?? raw.replaceAll("_", " "),
    tone = STATUS_TONES[raw] ?? "neutral";
  return (
    <span className={`badge ${tone}`}>
      <span className="dot" />
      {label}
    </span>
  );
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
        <input placeholder="Search" value={v} onChange={(e) => onChange(e.target.value)} />
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
      <option value="">{placeholder}</option>
      {options.map((x) => (
        <option key={x} value={x}>
          {x.replaceAll("_", " ")}
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
        Previous
      </button>
      <span>
        Page {p} / {pages}
      </span>
      <button className="button subtle" disabled={p >= pages} onClick={() => setOffset(offset + limit)}>
        Next
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
function Table({
  cols,
  rows,
  q,
  onRow,
  fields,
  sorting,
}: {
  cols: string[];
  rows: ReactNode[][];
  q?: any;
  onRow?: (i: number) => void;
  /** Column index → API field name. Only the named columns become sortable. */
  fields?: (string | null)[];
  sorting?: SortState;
}) {
  if (q?.isLoading)
    return (
      <div className="table-wrap">
        <div className="empty">Loading…</div>
      </div>
    );
  if (q?.isError)
    return (
      <div className="table-wrap">
        <div className="empty">
          <strong>{s(q.error)}</strong>
          <button className="button subtle" onClick={() => q.refetch()}>
            Try again
          </button>
        </div>
      </div>
    );
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {cols.map((x, i) => {
              const field = sorting && fields ? fields[i] : null;
              if (!field || !sorting) return <th key={x}>{x}</th>;
              const active = sorting.sort === field;
              return (
                <th key={x}>
                  <button
                    className={active ? "sort-button active" : "sort-button"}
                    onClick={() => sorting.toggle(field)}
                    aria-label={`Sort by ${x}`}
                  >
                    {x}
                    <span>{active ? (sorting.order === "desc" ? "▼" : "▲") : "↕"}</span>
                  </button>
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {rows.length ? (
            rows.map((r, i) => (
              <tr className={onRow ? "clickable" : ""} onClick={() => onRow?.(i)} key={i}>
                {r.map((x, j) => (
                  <td key={j}>{x}</td>
                ))}
              </tr>
            ))
          ) : (
            <tr className="empty-row">
              <td colSpan={cols.length}>
                <div className="empty">
                  <strong>Nothing to show here</strong>
                  <span>No record matches the current search and filters.</span>
                </div>
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
function Drawer({ title, close, children }: { title: string; close: () => void; children: ReactNode }) {
  return (
    <div className="drawer-backdrop" onClick={close}>
      <aside className="drawer" onClick={(e) => e.stopPropagation()}>
        <div className="drawer-head">
          <h2>{title}</h2>
          <button className="icon-button" onClick={close}>
            <X />
          </button>
        </div>
        <div className="drawer-body">{children}</div>
      </aside>
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
    collectedFrom = vals(q.data?.collected_from).join(", "),
    tiles: [string, unknown, string, string][] = [
      ["Open campaigns", m.campaigns, "/campaigns", "in progress"],
      ["Reviews waiting", m.pending_reviews, "/reviews", "to be decided"],
      ["Findings", m.findings, "/findings", "in the last collection"],
      ["Remediation actions", m.remediation_actions, "/actions", "to carry out"],
    ];
  if (q.isLoading) return <div className="empty">Loading…</div>;
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
            <div className="metric-label">{label}</div>
            <strong>{s(value, "0")}</strong>
            <small>{hint}</small>
          </NavLink>
        ))}
      </div>
      <div className="dashboard-grid">
        <section className="panel">
          <div className="panel-title">
            <h2>Needs attention</h2>
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
              Everything collected matches the expected state, and no campaign is waiting on anyone.
            </p>
          )}
        </section>
        <section className="panel">
          <div className="panel-title">
            <h2>Campaigns in progress</h2>
            <NavLink className="text-button" to="/campaigns">
              See all
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
                    {done} of {total} decided{row.due_at ? ` · due ${s(row.due_at)}` : ""}
                  </small>
                </div>
              );
            })
          ) : (
            <p className="muted">No campaign is open. Start one when a collection is up to date.</p>
          )}
          <div className="panel-title" style={{ marginTop: 24 }}>
            <h2>Sources</h2>
            <NavLink className="text-button" to="/sources">
              Manage
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
            <p className="muted">No source configured yet.</p>
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
    selected = debounce(search);
  const q = useQuery({
    queryKey: [path, selected, limit, offset, sort, order, extra],
    queryFn: () => getPage(path, { ...extra, search: selected, limit, offset, sort, order }),
  });
  // Any change of what is being listed sends the reader back to the first page.
  useEffect(() => setOffset(0), [selected, sort, order, JSON.stringify(extra)]);
  const sorting: SortState = {
    sort,
    order,
    toggle: (field: string) => {
      setOrder(sort === field && order === "asc" ? "desc" : "asc");
      setSort(field);
    },
  };
  return { q, search, setSearch, offset, setOffset, limit, setLimit, sorting };
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
        <SelectFilter
          value={provider}
          onChange={setProvider}
          options={["active_directory", "openldap"]}
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
        q={x.q}
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
    <Drawer title={s(identity.identifier)} close={close}>
      <h4>IDENTITY</h4>
      <p>{describeIdentity(identity) || "No description provided by the source."}</p>
      <p>
        {s(identity.type).replaceAll("_", " ")} · {s(identity.provider)} · <Status v={identity.status} />
      </p>
      {identity.account_owner ? (
        <p>Account owner: {s((identity.account_owner as Row | undefined)?.identity)}</p>
      ) : null}
      <h4>ACCESSES</h4>
      <Table
        cols={["Access", "Source", "Permission", "Mode", "State"]}
        q={q}
        rows={rows.map((r) => [
          <>
            <button
              className="link-button"
              onClick={() =>
                setAccess({
                  provider: r.access_provider ?? r.provider,
                  name: r.access_name,
                  permission: r.permission,
                  target: r.target,
                  description: r.description,
                })
              }
            >
              {s(r.access_name)}
            </button>
            <Sub>{describeAccess(r)}</Sub>
          </>,
          s(r.access_provider ?? r.provider),
          permissionText(r.permission) || "—",
          s(r.mode),
          <Status v={r.classification ?? "observed"} />,
        ])}
      />
      {access && <AccessDrawer access={access} close={() => setAccess(null)} />}
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
        <SelectFilter
          value={provider}
          onChange={setProvider}
          options={["active_directory", "openldap"]}
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
        fields={["display_name", "description", "provider", null, null, null, null]}
        sorting={x.sorting}
        q={x.q}
        rows={(x.q.data?.items ?? []).map((r) => [
          <button className="link-button" onClick={() => setSelected(r)}>
            {s(r.display_name, s(r.name))}
          </button>,
          <Sub>{describeAccess(r)}</Sub>,
          s(r.provider),
          permissionText(r.permission) || "—",
          targetText(r.target) || "—",
          s(r.assignment_count, "0"),
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
function AccessDrawer({ access, close }: { access: Row; close: () => void }) {
  const [tab, setTab] = useState("overview"),
    provider = s(access.provider),
    name = s(access.name ?? access.access_name),
    q = useQuery({
      queryKey: ["holders", provider, name],
      queryFn: () => getJson(`accesses/${encodeURIComponent(provider)}/${encodeURIComponent(name)}/holders`),
    });
  return (
    <Drawer title={name} close={close}>
      <div className="tabs">
        <button onClick={() => setTab("overview")}>Overview</button>
        <button onClick={() => setTab("holders")}>Holders</button>
      </div>
      {tab === "overview" ? (
        <>
          <h4>WHAT THIS ACCESS ALLOWS</h4>
          <p>{describeAccess(access) || "The source provided no description for this access."}</p>
          <h4>DETAILS</h4>
          <p>Source / application: {s(access.provider)}</p>
          <p>Permission: {permissionText(access.permission) || "—"}</p>
          <p>Target: {targetText(access.target) || "—"}</p>
          <p>
            Owner:{" "}
            {refText(access.access_owner) || s((access.access_owner as Row | undefined)?.identity, "—")}
          </p>
          <h4>WHO HOLDS IT</h4>
          <p>
            {arr(q.data?.holders).length} direct · {arr(q.data?.effective_holders).length} effective
            (inherited included)
          </p>
        </>
      ) : (
        <Table
          cols={["Identity", "Direct / Effective", "Why"]}
          q={q}
          rows={[
            ...arr(q.data?.holders).map((r) => ({ ...r, mode: "Direct" })),
            ...arr(q.data?.effective_holders).map((r) => ({ ...r, mode: "Effective" })),
          ].map((r: Row) => [
            s(r.identity_identifier),
            s(r.mode),
            r.mode === "Direct" ? "Direct grant" : "Effective provenance",
          ])}
        />
      )}
    </Drawer>
  );
}
function Reviews() {
  const campaigns = useQuery({
      queryKey: ["review-campaigns"],
      queryFn: () => getPage("campaigns", { limit: 100 }),
    }),
    [decision, setDecision] = useState(""),
    [campaign, setCampaign] = useState(""),
    x = useList("review-items", { status: decision, campaign }),
    [selected, setSelected] = useState<Row | null>(null);
  return (
    <>
      <Head title="My Reviews" />
      <Filter v={x.search} onChange={x.setSearch}>
        <SelectFilter
          value={campaign}
          onChange={setCampaign}
          options={arr(campaigns.data?.items).map((r) => s(r.id))}
          placeholder="Campaign"
        />
        <SelectFilter
          value={decision}
          onChange={setDecision}
          options={["pending", "approve", "revoke", "not_applicable"]}
          placeholder="Decision"
        />
      </Filter>
      <Table
        cols={["Identity", "Access", "Application", "Classification", "Latest decision"]}
        fields={[
          "identity_display_name",
          "access_display_name",
          "access_provider",
          "classification",
          "decision",
        ]}
        sorting={x.sorting}
        q={x.q}
        rows={[...(x.q.data?.items ?? [])]
          .sort((a, b) => Number(!a.decision) - Number(!b.decision))
          .map((r) => [
            <button className="link-button" onClick={() => setSelected(r)}>
              {s(r.identity_display_name, s(r.identity_identifier))}
            </button>,
            s(r.access_display_name, s(r.access_name)),
            targetText(r.target) || s(r.access_provider),
            <Status v={r.classification} />,
            <Status v={r.decision ?? "pending"} />,
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
    mutationFn: (v: string) => postDecision(s(item.id), v, v === "approve" ? undefined : reason.trim()),
    onSuccess: async () => {
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
    what = s(item.access_display_name, s(item.access_name));
  return (
    <Drawer title={`${who} → ${what}`} close={close}>
      <p className="muted">
        {s(item.access_provider)} · {s(item.identity_identifier)} · {s(item.access_name)}
      </p>
      <h4>WHAT THIS ACCESS ALLOWS</h4>
      <p>{describeAccess(item) || "The source provided no description for this access."}</p>
      <h4>WHY</h4>
      {item.direct ? (
        <p>
          <strong>Direct grant</strong>
        </p>
      ) : paths.length ? (
        <>
          {paths.map((p, i) => (
            <p className="path" key={i}>
              {arr(p.steps ?? p.access_chain).map((z, j) => (
                <span key={j}>
                  {j ? " → " : ""}
                  {s(z.name ?? z.identifier ?? z)}
                </span>
              ))}
            </p>
          ))}
        </>
      ) : (
        <p>Provenance not available</p>
      )}
      <h4>CURRENT STATE</h4>
      {currentStateLabels(Boolean(item.observed), Boolean(item.expected)).map((v) => (
        <p key={v}>{v}</p>
      ))}
      <h4>CLASSIFICATION</h4>
      <Status v={item.classification} />
      {pending && (
        <div className="reason-form">
          <label>
            Reason *<textarea autoFocus value={reason} onChange={(e) => setReason(e.target.value)} />
          </label>
          <button
            onClick={() => {
              setPending(null);
              setReason("");
            }}
          >
            Cancel
          </button>
          <button disabled={!reason.trim() || m.isPending} onClick={() => m.mutate(pending)}>
            Confirm {pending === "revoke" ? "revoke" : "N/A"}
          </button>
        </div>
      )}
      {!pending && (
        <div className="drawer-footer">
          <button onClick={() => setPending("not_applicable")}>N/A</button>
          <button onClick={() => setPending("revoke")}>Revoke</button>
          <button className="button primary" onClick={() => m.mutate("approve")}>
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
    [campaign, setCampaign] = useState(""),
    x = useList(path, { provider, status, campaign }),
    [selected, setSelected] = useState<Row | null>(null);
  return (
    <>
      <Head title={title} />
      <Filter v={x.search} onChange={x.setSearch}>
        <SelectFilter
          value={provider}
          onChange={setProvider}
          options={["active_directory", "openldap"]}
          placeholder="Source"
        />
        <SelectFilter
          value={status}
          onChange={setStatus}
          options={findings ? ["unexpected", "missing", "expected_and_observed"] : ["pending", "exported"]}
          placeholder="Status"
        />
        <SelectFilter
          value={campaign}
          onChange={setCampaign}
          options={arr(campaigns.data?.items).map((r) => s(r.id))}
          placeholder="Campaign"
        />
      </Filter>
      <Table
        cols={
          findings
            ? ["Classification", "Identity", "Access", "Source", "Campaign", "Observed", "Expected"]
            : ["Identity", "Requested action", "Access / Application", "Campaign", "Status"]
        }
        fields={
          findings
            ? ["classification", "identity_identifier", "access_name", "access_provider", null, null, null]
            : ["identity_display_name", "action", "access_display_name", "campaign_id", "status"]
        }
        sorting={x.sorting}
        q={x.q}
        rows={(x.q.data?.items ?? []).map((r) =>
          findings
            ? [
                <Status v={r.classification} />,
                <button className="link-button" onClick={() => setSelected(r)}>
                  {s((r.identity as Row | undefined)?.display_name, s(r.identity_identifier))}
                </button>,
                s((r.access as Row | undefined)?.display_name, s(r.access_name)),
                s(r.access_provider),
                s(r.campaign_id),
                s(r.observed),
                s(r.expected),
              ]
            : [
                <button className="link-button" onClick={() => setSelected(r)}>
                  {s(r.identity_display_name, s(r.identity_identifier))}
                </button>,
                s(r.action, s(r.decision)),
                s(r.access_display_name, s(r.access_name)),
                s(r.campaign_id),
                <Status v={r.status} />,
              ],
        )}
      />
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
  return (
    <Drawer title="Finding" close={close}>
      <h4>WHAT HAPPENED</h4>
      <p>{s(vals(row.findings).join(", "), s(row.classification, "No classification"))}</p>
      <h4>CURRENT STATE</h4>
      <p>
        Observed: {s(row.observed)} · Expected: {s(row.expected)}
      </p>
      <h4>CONTEXT</h4>
      <p>Identity: {s((row.identity as Row | undefined)?.display_name, s(row.identity_identifier))}</p>
      <p>Access: {s((row.access as Row | undefined)?.display_name, s(row.access_name))}</p>
      <p className="muted">{describeAccess((row.access as Row) ?? row)}</p>
      <p>Source: {s(row.access_provider)}</p>
      {row.campaign_id != null ? <p>Campaign: {s(row.campaign_id)}</p> : null}
    </Drawer>
  );
}
function ActionDrawer({ row, close }: { row: Row; close: () => void }) {
  return (
    <Drawer title={`${s(row.action, s(row.decision))} · ${s(row.access_name)}`} close={close}>
      <h4>WHAT TO DO</h4>
      <p>Identity: {s(row.identity_display_name, s(row.identity_identifier))}</p>
      <p>Access: {s(row.access_display_name, s(row.access_name))}</p>
      <p>{describeAccess(row) || "No description provided by the source."}</p>
      <p>Application / target: {targetText(row.target) || s(row.access_name)}</p>
      <h4>WHY</h4>
      <p>Campaign: {s(row.campaign_id)}</p>
      <p>Decision: {s(row.decision)}</p>
      <p>Comment: {s(row.comment)}</p>
      <h4>STATUS</h4>
      <Status v={row.status} />
    </Drawer>
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
          s(r.due_at),
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
function CampaignNew() {
  const snap = useQuery({ queryKey: ["snapshots"], queryFn: () => getPage("snapshots", { limit: 100 }) }),
    gold = useQuery({
      queryKey: ["golden-versions"],
      queryFn: () => getPage("golden-source-versions", { limit: 100 }),
    }),
    [form, setForm] = useState<Row>({
      name: "",
      snapshot_id: "",
      golden_source_version_id: "",
      due_at: "",
      scope_type: "all",
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
          },
        }),
      onSuccess: setPreview,
    }),
    toast = useToast(),
    create = useMutation({
      mutationFn: async (open: boolean) => {
        const { scope_type, providers, ...fields } = form;
        const payload = {
          ...fields,
          scope: {
            type: s(scope_type, "all"),
            ...(scope_type === "providers" ? { values: vals(providers) } : {}),
          },
          allow_unresolved_reviewers: allow,
        };
        const d = await postJson("campaigns", payload);
        if (open && d.id)
          await postJson("campaigns/" + s(d.id) + "/open", { allow_unresolved_reviewers: allow });
        return d;
      },
      onSuccess: (d) => {
        toast("ok", "Campaign created");
        if (d.id) window.location.href = "/campaigns/" + s(d.id);
      },
      onError: (e) => toast("error", s(e, "Unable to create the campaign")),
    }),
    snapshots = arr(snap.data?.items),
    versions = arr(gold.data?.items);
  useEffect(() => {
    if (!form.snapshot_id && snapshots.length)
      setForm((x) => ({ ...x, snapshot_id: s(snapshots[snapshots.length - 1].id) }));
    if (!form.golden_source_version_id && versions.length)
      setForm((x) => ({ ...x, golden_source_version_id: s(versions[versions.length - 1].id) }));
  }, [snapshots.length, versions.length]);
  return (
    <>
      <Head title="New campaign">
        <NavLink className="button subtle" to="/campaigns">
          Cancel
        </NavLink>
      </Head>
      <section className="panel">
        <h2>Campaign setup</h2>
        <form
          className="admin-form"
          onSubmit={(e) => {
            e.preventDefault();
            previewM.mutate();
          }}
        >
          <label>
            Name
            <input
              required
              value={s(form.name, "")}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
          </label>
          <label>
            Scope
            <select
              value={s(form.scope_type, "all")}
              onChange={(e) => setForm({ ...form, scope_type: e.target.value })}
            >
              <option value="all">All</option>
              <option value="providers">Provider(s)</option>
            </select>
          </label>
          <label>
            Snapshot
            <select
              required
              value={s(form.snapshot_id, "")}
              onChange={(e) => setForm({ ...form, snapshot_id: e.target.value })}
            >
              <option value="">Select snapshot</option>
              {snapshots.map((r) => (
                <option key={s(r.id)} value={s(r.id)}>
                  {s(r.created_at)} · {s(r.assignment_count, "assignments unavailable")}
                </option>
              ))}
            </select>
          </label>
          <label>
            Golden Source version
            <select
              value={s(form.golden_source_version_id, "")}
              onChange={(e) => setForm({ ...form, golden_source_version_id: e.target.value || undefined })}
            >
              <option value="">None</option>
              {versions.map((r) => (
                <option key={s(r.id)} value={s(r.id)}>
                  v{s(r.version)} · {s(r.id)}
                </option>
              ))}
            </select>
          </label>
          <label>
            Due date
            <input
              type="date"
              value={s(form.due_at, "")}
              onChange={(e) => setForm({ ...form, due_at: e.target.value || undefined })}
            />
          </label>
          <button className="button primary" type="submit" disabled={previewM.isPending}>
            Preview campaign
          </button>
        </form>
      </section>
      {preview && (
        <section className="panel">
          <h2>Campaign preview</h2>
          <div className="metrics">
            <div className="metric">
              <strong>{s(preview.total_review_items, "0")}</strong>
              <small>Review items</small>
            </div>
            <div className="metric">
              <strong>{s(preview.resolved_reviewers, "0")}</strong>
              <small>Reviewers resolved</small>
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
              disabled={(!allow && Number(preview.unresolved_reviewers) > 0) || create.isPending}
              onClick={() => create.mutate(false)}
            >
              Save as draft
            </button>
            <button
              className="button primary"
              disabled={(!allow && Number(preview.unresolved_reviewers) > 0) || create.isPending}
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
        q.refetch();
      },
      onError: (e) => toast("error", s(e, "This operation was refused")),
    }),
    reviews = arr(q.data?.reviews),
    findings = arr(q.data?.findings),
    status = s(c?.status),
    pending = reviews.filter((r) => !r.decision).length,
    ctas = campaignCtas(status, pending);
  if (!c) return <div className="empty">{q.isLoading ? "Loading..." : "Campaign not found"}</div>;
  return (
    <>
      <Head title={s(c.name)}>
        <div className="button-row">
          <NavLink to="/campaigns">Back</NavLink>
          {ctas.map((a) => (
            <button
              className="button subtle"
              key={a}
              disabled={a === "close-disabled"}
              onClick={() => m.mutate(a.replace("-disabled", ""))}
            >
              {a}
            </button>
          ))}
        </div>
      </Head>
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
        <section className="panel">
          <h2>Campaign overview</h2>
          <p>
            Status: <Status v={c.status} />
          </p>
          <p>Progress: {pct(c.progress)}%</p>
          <p>Snapshot: {s(c.snapshot_id)}</p>
          <p>Golden version: {s(c.golden_source_version_id)}</p>
          <p>Scope: {s((c.scope as Row | undefined)?.type, "all")}</p>
          <p>
            Review items: {reviews.length} - Pending: {pending}
          </p>
        </section>
      )}
      {tab === "reviews" && (
        <Table
          cols={["Identity", "Access", "Classification", "Decision"]}
          rows={reviews.map((r) => [
            <button className="link-button" onClick={() => setSelected(r)}>
              {s(r.identity_display_name, s(r.identity_identifier))}
            </button>,
            s(r.access_display_name, s(r.access_name)),
            <Status v={r.classification} />,
            <Status v={r.decision ?? "pending"} />,
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
    </>
  );
}
const goldenOrigin = (row: Row) => {
  const kind = s(row.source_type);
  if (kind === "promoted_campaign") return `Promoted from campaign ${s(row.source_campaign_id, "—")}`;
  if (kind === "snapshot" || kind === "baseline")
    return `Adopted from what the systems contained on ${s(row.created_at)}`;
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
function Golden() {
  const c = useQueryClient(),
    q = useQuery({ queryKey: ["golden"], queryFn: () => getPage("golden-sources", { limit: 100 }) }),
    snap = useQuery({ queryKey: ["snap"], queryFn: () => getPage("snapshots", { limit: 100 }) }),
    source = arr(q.data?.items)[0],
    sourceName = s(source?.name, ""),
    encoded = encodeURIComponent(sourceName),
    [compare, setCompare] = useState<Row | null>(null),
    [notice, setNotice] = useState<{ tone: string; text: string } | null>(null),
    [name, setName] = useState("Main baseline"),
    [sid, setSid] = useState(""),
    [tab, setTab] = useState("expected"),
    [adding, setAdding] = useState<Row | null>(null),
    [removing, setRemoving] = useState<Row | null>(null),
    [search, setSearch] = useState(""),
    selected = debounce(search),
    [offset, setOffset] = useState(0),
    [limit, setLimit] = useState(25),
    content = useQuery({
      queryKey: ["golden-assignments", sourceName, selected, limit, offset],
      queryFn: () => getJson(`golden-sources/${encoded}/assignments`, { search: selected, limit, offset }),
      enabled: Boolean(sourceName),
      retry: false,
    }),
    expected = arr(content.data?.items),
    history = arr(content.data?.versions),
    refresh = async () => {
      await Promise.all([q.refetch(), c.invalidateQueries({ queryKey: ["golden-assignments"] })]);
    },
    baseline = useMutation({
      mutationFn: () => postJson("golden-sources/baseline", { name, snapshot_id: sid }),
      onSuccess: async (d) => {
        setNotice({
          tone: "ok",
          text: `Baseline created · v${s((d.version as Row | undefined)?.version, "1")}`,
        });
        await refresh();
      },
      onError: (e) => setNotice({ tone: "error", text: s(e, "Unable to create the baseline") }),
    }),
    edit = useMutation({
      mutationFn: (body: Row) => postJson(`golden-sources/${encoded}/assignments`, body),
      onSuccess: async (d) => {
        setAdding(null);
        setRemoving(null);
        setNotice({
          tone: "ok",
          text: `Version v${s(d.version)} created · ${s(d.assignments)} expected access(es)`,
        });
        await refresh();
      },
      onError: (e) => setNotice({ tone: "error", text: s(e, "Unable to change the Golden Source") }),
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
      {notice && <p className={notice.tone === "ok" ? "muted" : "form-error"}>{notice.text}</p>}
      {!source ? (
        <section className="panel">
          <h2>No expected state yet</h2>
          {snapshots.length ? (
            <>
              <p>
                Start from what the systems contain today: EARE reads the latest collected state and declares
                it expected. You can then correct it access by access.
              </p>
              <p className="muted">
                Latest collection: {s(latest?.created_at)} ·{" "}
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
                  Collected state to adopt
                  <select value={sid} onChange={(e) => setSid(e.target.value)}>
                    {snapshots.map((r) => (
                      <option key={s(r.id)} value={s(r.id)}>
                        {s(r.created_at)} ·{" "}
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
          ) : (
            <>
              <p>Nothing has been collected yet, so there is no state to declare as expected.</p>
              <p className="muted">Synchronize a source first, then come back here.</p>
              <NavLink className="button subtle" to="/sources">
                Go to Sources &amp; IdPs
              </NavLink>
            </>
          )}
        </section>
      ) : (
        <>
          <section className="panel">
            <h2>{s(source.display_name, sourceName)}</h2>
            <p>
              <strong>v{s(content.data?.version, "—")}</strong> · {s(content.data?.total, "0")} expected
              access(es)
            </p>
            <p className="muted">
              {content.data ? goldenOrigin(content.data as Row) : "Loading…"}
              {content.data?.comment ? ` · ${s(content.data.comment)}` : ""}
            </p>
          </section>
          <div className="tabs">
            <button
              className={tab === "expected" ? "text-button active" : "text-button"}
              onClick={() => setTab("expected")}
            >
              Expected access
            </button>
            <button
              className={tab === "changes" ? "text-button active" : "text-button"}
              onClick={() => setTab("changes")}
            >
              Changes since the last collection
            </button>
            <button
              className={tab === "history" ? "text-button active" : "text-button"}
              onClick={() => setTab("history")}
            >
              Version history
            </button>
          </div>
          {tab === "expected" && (
            <>
              <Filter v={search} onChange={setSearch}>
                <button className="button subtle" onClick={() => setAdding(blankExpected())}>
                  + Add expected access
                </button>
              </Filter>
              <Table
                cols={["Identity", "Source", "Access", "Permission", ""]}
                q={content}
                rows={expected.map((r) => [
                  s(r.identity_identifier),
                  s(r.access_provider),
                  s(r.access_name),
                  s(r.access_permission),
                  <button className="link-button" onClick={() => setRemoving(r)}>
                    Remove
                  </button>,
                ])}
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
                  <h2>{counted("added") + counted("removed")} change(s) since the last collection</h2>
                  <div className="diff-summary">
                    <strong>{counted("added")} to become expected</strong>
                    <strong>{counted("removed")} no longer present</strong>
                    <strong>{counted("unchanged")} unchanged</strong>
                  </div>
                  <Table
                    cols={["Change", "Identity", "Access", "Source"]}
                    rows={changes
                      .filter((r) => r.status !== "unchanged")
                      .map((r) => [
                        <Status v={r.status === "added" ? "added" : "removed"} />,
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
          {tab === "history" && (
            <Table
              cols={["Version", "Origin", "Created", "Expected access"]}
              q={content}
              rows={[...history]
                .reverse()
                .map((r) => [
                  <strong>v{s(r.version)}</strong>,
                  goldenOrigin(r),
                  s(r.created_at),
                  s(r.assignments, "0"),
                ])}
            />
          )}
        </>
      )}
      {adding && (
        <Drawer title="Add an expected access" close={() => setAdding(null)}>
          <p className="muted">
            Declaring an access expected creates a new version. Nothing changes in the audited systems.
          </p>
          <form
            className="admin-form"
            onSubmit={(e) => {
              e.preventDefault();
              edit.mutate({ add: [adding] });
            }}
          >
            <label>
              Identity
              <input
                required
                placeholder="alice.martin"
                value={s(adding.identity_identifier, "")}
                onChange={(e) => setAdding({ ...adding, identity_identifier: e.target.value })}
              />
            </label>
            <label>
              Identity source
              <input
                required
                placeholder="corp-ad"
                value={s(adding.identity_provider, "")}
                onChange={(e) => setAdding({ ...adding, identity_provider: e.target.value })}
              />
            </label>
            <label>
              Access
              <input
                required
                placeholder="GRP-Finance-RW"
                value={s(adding.access_name, "")}
                onChange={(e) => setAdding({ ...adding, access_name: e.target.value })}
              />
            </label>
            <label>
              Access source
              <input
                required
                placeholder="corp-ad"
                value={s(adding.access_provider, "")}
                onChange={(e) => setAdding({ ...adding, access_provider: e.target.value })}
              />
            </label>
            <label>
              Permission
              <input
                value={s(adding.access_permission, "")}
                onChange={(e) => setAdding({ ...adding, access_permission: e.target.value })}
              />
            </label>
            <button className="button primary" type="submit" disabled={edit.isPending}>
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
                {s(removing.identity_identifier)} → {s(removing.access_name)} ({s(removing.access_provider)})
                stops being expected. If the systems still grant it, the next review reports it as unexpected.
              </p>
              <p className="muted">A new version is recorded. The current one stays in the history.</p>
            </>
          }
          confirmLabel="Remove from the expected state"
          danger
          pending={edit.isPending}
          cancel={() => setRemoving(null)}
          confirm={() => edit.mutate({ remove: [removing] })}
        />
      )}
    </>
  );
}
function Sources() {
  const toast = useToast(),
    q = useQuery({ queryKey: ["providers"], queryFn: () => getPage("providers", { limit: 100 }) }),
    cfg = useQuery({ queryKey: ["source-configs"], queryFn: () => getJson("system/sources") }),
    [job, setJob] = useState(""),
    [kind, setKind] = useState("preview"),
    [error, setError] = useState(""),
    [editing, setEditing] = useState<Row | null>(null),
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
      onSuccess: (d) => setError(s(d.message, "Connection test succeeded")),
      onError: (e) => setError(s(e, "Source connection test failed")),
    }),
    jq = useQuery({
      queryKey: ["job", job],
      queryFn: () => getJson(`jobs/${job}`),
      enabled: !!job,
      refetchInterval: 1500 as const,
    }),
    configs = arr(cfg.data?.sources),
    observed = arr(q.data?.items),
    sources = configs.map((c) => ({ ...c, ...(observed.find((o) => s(o.name) === s(c.provider)) || {}) }));
  const blank = () => ({
    provider: "",
    type: "active_directory",
    connection: { server: "" },
    collection: { timeout: 300, allow_partial: false },
    credentials: { username_env: "", password_env: "" },
  });
  const edit = (source?: Row) => {
    setError("");
    setEditing(source ? JSON.parse(JSON.stringify(source)) : blank());
  };
  const update = (key: string, value: unknown) => setEditing((x) => (x ? { ...x, [key]: value } : x));
  const updateNested = (section: string, key: string, value: unknown) =>
    setEditing((x) => (x ? { ...x, [section]: { ...((x[section] as Row) || {}), [key]: value } } : x));
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
              <span>{s(r.last_sync, "Never synced")}</span>
            </div>
            <h2>{s(r.display_name, s(r.provider))}</h2>
            <p>
              {s(r.type).toUpperCase()} · {s(r.provider)}
            </p>
            <div className="source-stats">
              <div>
                <strong>{s(r.identity_count, "0")}</strong>
                <span>Identities</span>
              </div>
              <div>
                <strong>{s(r.group_count, "0")}</strong>
                <span>Groups</span>
              </div>
              <div>
                <strong>{s(r.access_count, "0")}</strong>
                <span>Accesses</span>
              </div>
            </div>
            <div className="source-foot">
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
          {jq.data?.result ? <pre>{JSON.stringify(jq.data.result, null, 2)}</pre> : null}
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
              </>
            )}
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
          s(r.created_at),
          s(r.actor),
          s(r.event_type),
          s(r.object_type) + " / " + s(r.object_id),
          s(r.details),
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
  const q = useQuery({ queryKey: ["reports"], queryFn: () => getPage("campaigns", { limit: 100 }) }),
    [campaign, setCampaign] = useState("");
  const campaigns = arr(q.data?.items),
    selected = campaigns.find((r) => s(r.id) === campaign) || campaigns[0];
  return (
    <>
      <Head title="Reports" />
      <div className="filterbar">
        <select
          className="filter-button"
          value={s(selected?.id, "")}
          onChange={(e) => setCampaign(e.target.value)}
        >
          <option value="">Select campaign</option>
          {campaigns.map((r) => (
            <option key={s(r.id)} value={s(r.id)}>
              {s(r.name)}
            </option>
          ))}
        </select>
      </div>
      {selected ? (
        <section className="panel">
          <h2>{s(selected.name)} reports</h2>
          <div className="report-list">
            <div className="report-row">
              <strong>Campaign review report</strong>
              <a href={`/api/reports/${s(selected.id)}/html`}>HTML</a>
            </div>
            <div className="report-row">
              <strong>Campaign results</strong>
              <a href={`/api/reports/${s(selected.id)}/csv`}>CSV</a>
            </div>
            <div className="report-row">
              <strong>Campaign evidence</strong>
              <a href={`/api/reports/${s(selected.id)}/json`}>JSON</a>
            </div>
          </div>
        </section>
      ) : (
        <div className="empty">No campaign available.</div>
      )}
    </>
  );
}
const LOCAL_SOURCE = "local";
const blankUser = (source = LOCAL_SOURCE): Row => ({
  username: "",
  display_name: "",
  role: "OPERATOR",
  scopes: "",
  password: "",
  enabled: true,
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
    source = s(form.auth_source, LOCAL_SOURCE),
    fromDirectory = source !== LOCAL_SOURCE,
    m = useMutation({
      mutationFn: () => {
        const scopes = String(form.scopes || "")
          .split(",")
          .map((x) => x.trim())
          .filter(Boolean);
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
    setForm(r ? { ...r, scopes: vals(r.scopes).join(", "), password: "" } : blankUser());
    setOpen(true);
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
        cols={["User", "Username", "Signs in with", "Role", "Scope", "Pending reviews", "Status", "Actions"]}
        q={q}
        rows={users.map((r) => [
          s(r.display_name),
          s(r.username),
          s(r.auth_source, LOCAL_SOURCE) === LOCAL_SOURCE ? "Local account" : s(r.auth_source),
          <Status v={r.role} />,
          s(vals(r.scopes).join(", "), "All"),
          Number(r.pending_reviews) > 0 ? s(r.pending_reviews) : "—",
          <>
            <Status v={r.enabled ? "enabled" : "disabled"} />
            {r.must_change_password ? <span className="muted"> · password change required</span> : null}
          </>,
          <div className="row-actions">
            <button className="link-button" onClick={() => edit(r)}>
              Edit
            </button>
            {s(r.auth_source, LOCAL_SOURCE) === LOCAL_SOURCE && (
              <button
                className="link-button"
                onClick={() => {
                  setError("");
                  setNotice("");
                  setNewPassword("");
                  setConfirming({ action: "reset-password", user: r });
                }}
              >
                Reset password
              </button>
            )}
            {Number(r.pending_reviews) > 0 && (
              <button
                className="link-button"
                onClick={() => {
                  setError("");
                  setNotice("");
                  setReassignTo("");
                  setConfirming({ action: "reassign", user: r });
                }}
              >
                Reassign reviews
              </button>
            )}
            <button
              className="link-button"
              onClick={() => {
                setError("");
                setNotice("");
                setConfirming({ action: r.enabled ? "disable" : "enable", user: r });
              }}
            >
              {r.enabled ? "Disable" : "Enable"}
            </button>
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
          title={form.id ? "Edit user" : fromDirectory ? "Import user" : "New local user"}
          close={() => setOpen(false)}
        >
          <form
            className="admin-form"
            onSubmit={(e) => {
              e.preventDefault();
              m.mutate();
            }}
          >
            <h4>ACCOUNT</h4>
            <label>
              Username
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
              <select value={s(form.role)} onChange={(e) => setForm({ ...form, role: e.target.value })}>
                <option>ADMIN</option>
                <option>OPERATOR</option>
                <option>GROUP_OWNER</option>
                <option>BUSINESS_ADMIN</option>
              </select>
            </label>
            <p className="field-note">{roleHelp(s(form.role))}</p>
            <label>
              Scopes
              <input
                placeholder="provider-a, provider-b"
                value={s(form.scopes, "")}
                onChange={(e) => setForm({ ...form, scopes: e.target.value })}
              />
            </label>
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
    return "Runs collections, manages the Golden Source, campaigns, findings and reports.";
  if (role === "GROUP_OWNER") return "Only sees and decides the reviews assigned to this person.";
  return "Only sees the remediation actions of the sources listed in Scopes.";
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
      {notice && <p className={notice.tone === "ok" ? "muted" : "form-error"}>{notice.text}</p>}
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
            {notice && <p className={notice.tone === "ok" ? "muted" : "form-error"}>{notice.text}</p>}
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
