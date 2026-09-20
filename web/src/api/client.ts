export type Row = Record<string, unknown>;

export type Principal = {
  subject: string;
  username: string;
  display_name: string;
  role: string;
  scopes: string[];
  must_change_password: boolean;
};
export type Params = Record<string, string | number | boolean | undefined>;

async function request(path: string, init: RequestInit = {}): Promise<unknown> {
  const response = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...init.headers,
    },
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as { detail?: string };
    throw new Error(body.detail ?? `Request failed (${response.status})`);
  }
  return response.status === 204 ? null : response.json();
}

function queryString(params: Params): string {
  const query = new URLSearchParams(
    Object.entries(params)
      .filter(([, value]) => value !== undefined && value !== "")
      .map(([key, value]) => [key, String(value)]),
  );
  return query.size ? `?${query}` : "";
}

export async function getSession(): Promise<Principal> {
  return request("/api/auth/session") as Promise<Principal>;
}
export async function login(username: string, password: string): Promise<Principal> {
  return request("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  }) as Promise<Principal>;
}
export async function logout(): Promise<void> {
  await request("/api/auth/logout", { method: "POST" });
}
export async function changePassword(newPassword: string): Promise<Principal> {
  return request("/api/auth/change-password", {
    method: "POST",
    body: JSON.stringify({ new_password: newPassword }),
  }) as Promise<Principal>;
}
export async function getJson(path: string, params: Params = {}): Promise<Row> {
  return request(`/api/${path}${queryString(params)}`) as Promise<Row>;
}
export async function getRows(path: string, params: Params = {}): Promise<Row[]> {
  const body = (await getJson(path, params)) as { items?: Row[] } | Row[];
  return Array.isArray(body) ? body : (body.items ?? []);
}
export type Page = {
  items: Row[];
  total: number;
  limit: number;
  offset: number;
  /** Counts over the whole filtered set, not only the page. Review lists carry one. */
  summary?: Row;
};
export async function getPage(path: string, params: Params = {}): Promise<Page> {
  const body = (await getJson(path, params)) as Partial<Page>;
  return {
    items: body.items ?? [],
    total: Number(body.total ?? 0),
    limit: Number(body.limit ?? 25),
    offset: Number(body.offset ?? 0),
    ...(body.summary ? { summary: body.summary } : {}),
  };
}
export async function postJson(path: string, body?: Row): Promise<Row> {
  return request(`/api/${path}`, {
    method: "POST",
    body: body ? JSON.stringify(body) : undefined,
  }) as Promise<Row>;
}
export async function putJson(path: string, body: Row): Promise<Row> {
  return request(`/api/${path}`, {
    method: "PUT",
    body: JSON.stringify(body),
  }) as Promise<Row>;
}
export async function postDecision(id: string, value: string, comment?: string): Promise<Row> {
  return postJson(`review-items/${encodeURIComponent(id)}/decision`, {
    value,
    ...(comment === undefined ? {} : { comment }),
  });
}
export function currentStateLabels(observed: boolean, expected: boolean): string[] {
  return ["Observed " + (observed ? "✓" : "Not observed"), "Expected " + (expected ? "✓" : "Not expected")];
}
