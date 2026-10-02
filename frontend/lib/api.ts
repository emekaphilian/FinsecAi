declare global {
  interface Window {
    __FINSECAI_API_URL?: string;
  }
}

const API_URL =
  (typeof window !== "undefined" ? window.__FINSECAI_API_URL : undefined) ||
  process.env.NEXT_PUBLIC_API_URL ||
  "http://localhost:8001";

if (typeof window !== "undefined") {
  console.info("FinSecAI API:", API_URL);
}

export interface FrontendSession {
  role: string;
  tenant_id: string | null;
  email?: string;
  must_change_password?: boolean;
}

const SESSION_KEY = "finsecai_session";
const ACTIVE_TENANT_KEY = "finsecai_active_tenant";
const REFRESH_TOKEN_KEY = "finsecai_refresh_token";
let refreshPromise: Promise<boolean> | null = null;

export function scopedQuery(tenantId?: string | null): string {
  return tenantId ? `?tenant_id=${encodeURIComponent(tenantId)}` : "";
}

function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("finsecai_token");
}

export function setToken(token: string) {
  localStorage.setItem("finsecai_token", token);
}

function getRefreshToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

function clearBrowserAuthState() {
  if (typeof window === "undefined") return;
  localStorage.removeItem("finsecai_token");
  localStorage.removeItem(REFRESH_TOKEN_KEY);
  clearSession();
}

export function clearToken() {
  const refreshToken = getRefreshToken();
  clearBrowserAuthState();
  if (refreshToken) {
    void fetch(`${API_URL}/auth/logout`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    }).catch(() => undefined);
  }
}

export function getSession(): FrontendSession | null {
  if (typeof window === "undefined") {
    return null;
  }

  const raw = sessionStorage.getItem(SESSION_KEY);

  if (!raw) {
    return null;
  }

  try {
    return JSON.parse(raw) as FrontendSession;
  } catch {
    sessionStorage.removeItem(SESSION_KEY);
    return null;
  }
}

export function clearSession(): void {
  if (typeof window === "undefined") {
    return;
  }

  sessionStorage.removeItem(SESSION_KEY);
  sessionStorage.removeItem(ACTIVE_TENANT_KEY);
}

export function getActiveTenantId(): string | null {
  if (typeof window === "undefined") {
    return null;
  }

  return sessionStorage.getItem(ACTIVE_TENANT_KEY);
}

export function setActiveTenantId(tenantId: string | null): void {
  if (typeof window === "undefined") {
    return;
  }

  if (tenantId) {
    sessionStorage.setItem(ACTIVE_TENANT_KEY, tenantId);
  } else {
    sessionStorage.removeItem(ACTIVE_TENANT_KEY);
  }
}

function authRedirectPath(): string {
  const session = getSession();
  if (session?.role === "owner") return "/owner-login";
  if (session?.tenant_id) return "/tenant-login";
  return "/login?demo=1";
}

function redirectAfterAuthFailure() {
  if (typeof window === "undefined") return;
  const path = authRedirectPath();
  if (!window.location.pathname.endsWith(path.split("?")[0])) {
    window.location.href = path;
  }
}

async function refreshAccessToken(): Promise<boolean> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) return false;
  if (!refreshPromise) {
    refreshPromise = fetch(`${API_URL}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    })
      .then(async (res) => {
        if (!res.ok) return false;
        const data = await res.json();
        setToken(data.access_token);
        localStorage.setItem(REFRESH_TOKEN_KEY, data.refresh_token);
        sessionStorage.setItem(
          SESSION_KEY,
          JSON.stringify({
            role: data.role,
            tenant_id: data.tenant_id ?? null,
            email: data.email,
            must_change_password: data.must_change_password ?? false,
          })
        );
        return true;
      })
      .catch(() => false)
      .finally(() => {
        refreshPromise = null;
      });
  }
  return refreshPromise;
}

export async function downloadReport(id: string) {
  const token = getToken();

  const res = await fetch(`${API_URL}/reports/${id}`, {
    method: "POST",
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });

  if (res.status === 401) {
    const refreshed = await refreshAccessToken();
    if (refreshed) {
      return downloadReport(id);
    }
    clearToken();

    redirectAfterAuthFailure();

    return;
  }

  if (!res.ok) {
    const detail = await res.text();
    alert(`Report generation failed - ${res.status}: ${detail}`);
    return;
  }

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `report_${id}.pdf`;
  a.click();
  URL.revokeObjectURL(url);
}

export async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
  hasRetried = false
): Promise<T> {
  const token = getToken();

  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, {
      ...options,
      headers: {
        ...(options.body instanceof FormData
          ? {}
          : { "Content-Type": "application/json" }),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...options.headers,
      },
    });
  } catch {
    throw new Error(`Cannot reach the API at ${API_URL}${path}. Check NEXT_PUBLIC_API_URL and the backend CORS settings.`);
  }

  if (res.status === 401) {
    if (!hasRetried && (await refreshAccessToken())) {
      return apiFetch<T>(path, options, true);
    }
    clearToken();
    redirectAfterAuthFailure();

    throw new Error("Session expired");
  }

  if (!res.ok) {
    const text = await res.text();
    let detail = text;
    try {
      const body = JSON.parse(text) as { detail?: string };
      detail = body.detail || text;
    } catch {
      // Non-JSON errors (for example proxy failures) are still useful as-is.
    }
    throw new Error(detail ? `${res.status}: ${detail}` : `Request failed (${res.status})`);
  }

  return res.json();
}

export async function login(email: string, password: string, context: "demo" | "tenant" | "owner" | "any" = "any") {
  const body = new URLSearchParams({
    username: email,
    password,
  });

  const path = context === "any" ? "/auth/login" : `/auth/${context}/login`;
  const res = await fetch(`${API_URL}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  });

  const text = await res.text();

  if (!res.ok) {
    throw new Error(`${res.status}: ${text}`);
  }

  try {
    const data = JSON.parse(text);
    setToken(data.access_token);
    if (data.refresh_token) {
      localStorage.setItem(REFRESH_TOKEN_KEY, data.refresh_token);
    } else {
      localStorage.removeItem(REFRESH_TOKEN_KEY);
    }
    sessionStorage.setItem(
      SESSION_KEY,
      JSON.stringify({
        role: data.role,
        tenant_id: data.tenant_id ?? null,
        email,
        must_change_password: data.must_change_password ?? false,
      })
    );
    return data;
  } catch {
    throw new Error(`Invalid JSON response: ${text}`);
  }
}

export async function changeCredentials(currentPassword: string, newPassword: string, newEmail?: string) {
  const data = await apiFetch<{
    access_token: string;
    role: string;
    tenant_id: string | null;
    email: string;
    must_change_password: boolean;
    refresh_token?: string | null;
  }>("/auth/credentials", {
    method: "POST",
    body: JSON.stringify({
      current_password: currentPassword,
      new_password: newPassword,
      ...(newEmail ? { new_email: newEmail } : {}),
    }),
  });
  setToken(data.access_token);
  if (data.refresh_token) {
    localStorage.setItem(REFRESH_TOKEN_KEY, data.refresh_token);
  }
  sessionStorage.setItem(SESSION_KEY, JSON.stringify({
    role: data.role,
    tenant_id: data.tenant_id ?? null,
    email: data.email,
    must_change_password: data.must_change_password,
  }));
  return data;
}

export async function enterTenantWorkspace(tenantId: string) {
  return apiFetch<{ tenant_id: string; name: string }>(`/tenants/${tenantId}/workspace`, {
    method: "POST",
  });
}

export function copilotSocketUrl(tenantId?: string | null): string {
  const token = getToken();
  const wsBase = API_URL.replace(/^http/, "ws");
  const tenantQuery = tenantId ? `&tenant_id=${encodeURIComponent(tenantId)}` : "";
  return `${wsBase}/ws/copilot?token=${token}${tenantQuery}`;
}
