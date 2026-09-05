import type { TokenStore } from "./types.js";

export type BrowserFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

export class LotorBrowserError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code: string,
  ) {
    super(message);
    this.name = "LotorBrowserError";
  }
}

export interface BrowserRequestTransport {
  request<T>(path: string, init?: RequestInit, authenticated?: boolean): Promise<T>;
  requestWithMetadata<T>(path: string, init?: RequestInit, authenticated?: boolean): Promise<{ body: T; headers: Headers }>;
}

export class BrowserTransport {
  constructor(
    private readonly baseUrl: string,
    private readonly fetcher: BrowserFetch,
    private readonly tokenStore: TokenStore,
    private readonly publishableKey: string,
  ) {}

  async request<T>(path: string, init: RequestInit = {}, authenticated = false): Promise<T> {
    return (await this.requestWithMetadata<T>(path, init, authenticated)).body;
  }

  async requestWithMetadata<T>(path: string, init: RequestInit = {}, authenticated = false): Promise<{ body: T; headers: Headers }> {
    const headers = new Headers(init.headers);
    headers.set("X-Lotor-Publishable-Key", this.publishableKey);
    if (init.body !== undefined && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }
    if (authenticated) {
      const token = (await this.tokenStore.getToken())?.trim();
      if (!token) {
        throw new LotorBrowserError("Lotor request requires authentication", 401, "unauthenticated");
      }
      headers.set("Authorization", `Bearer ${token}`);
    }
    const response = await this.fetcher(`${this.baseUrl}${path}`, {
      ...init,
      headers,
      credentials: "omit",
    });
    if (!response.ok) {
      throw browserResponseError(response.status);
    }
    if (response.status === 204) {
      return { body: undefined as T, headers: response.headers };
    }
    return { body: await response.json() as T, headers: response.headers };
  }
}

export type CSRFTokenProvider = () => string | null | Promise<string | null>;

/** Cookie-authenticated transport for a Lotor gateway mounted on the application origin. */
export class SameOriginBrowserTransport implements BrowserRequestTransport {
  constructor(
    private readonly fetcher: BrowserFetch,
    private readonly publishableKey: string,
    private readonly csrfToken: CSRFTokenProvider = browserCSRFCookie,
  ) {}

  async request<T>(path: string, init: RequestInit = {}, authenticated = false): Promise<T> {
    return (await this.requestWithMetadata<T>(path, init, authenticated)).body;
  }

  async requestWithMetadata<T>(path: string, init: RequestInit = {}, authenticated = false): Promise<{ body: T; headers: Headers }> {
    if (!path.startsWith("/.lotor/v1/") && path !== "/.lotor/v1/session") {
      throw new Error("same-origin Lotor paths must use the reserved gateway prefix");
    }
    const headers = new Headers(init.headers);
    headers.delete("Authorization");
    headers.set("X-Lotor-Publishable-Key", this.publishableKey);
    if (init.body !== undefined && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    const method = (init.method ?? "GET").toUpperCase();
    const safe = method === "GET" || method === "HEAD" || method === "OPTIONS";
    if (authenticated && !safe) {
      const token = (await this.csrfToken())?.trim();
      if (!token) throw new LotorBrowserError("Lotor CSRF proof is unavailable", 403, "csrf_unavailable");
      headers.set("X-Lotor-CSRF", token);
    }
    const response = await this.fetcher(path, { ...init, headers, credentials: "same-origin" });
    if (!response.ok) throw browserResponseError(response.status);
    if (response.status === 204) return { body: undefined as T, headers: response.headers };
    return { body: await response.json() as T, headers: response.headers };
  }
}

function browserCSRFCookie(): string | null {
  if (typeof document === "undefined") return null;
  for (const part of document.cookie.split(";")) {
    const [rawName, ...rawValue] = part.trim().split("=");
    if (rawName === "__Host-lotor_csrf" || rawName === "lotor_dev_csrf") {
      try { return decodeURIComponent(rawValue.join("=")); } catch { return null; }
    }
  }
  return null;
}

function browserResponseError(status: number): LotorBrowserError {
  const code = ({
    400: "invalid_request",
    401: "unauthenticated",
    403: "forbidden",
    404: "not_found",
    409: "idempotency_conflict",
    429: "rate_limited",
    503: "unavailable",
  } as Record<number, string>)[status] ?? "request_failed";
  return new LotorBrowserError(`Lotor request failed with status ${status}`, status, code);
}
