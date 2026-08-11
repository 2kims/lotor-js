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

export class BrowserTransport {
  constructor(
    private readonly baseUrl: string,
    private readonly fetcher: BrowserFetch,
    private readonly tokenStore: TokenStore,
  ) {}

  async request<T>(path: string, init: RequestInit = {}, authenticated = false): Promise<T> {
    const headers = new Headers(init.headers);
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
      const code = ({
        400: "invalid_request",
        401: "unauthenticated",
        403: "forbidden",
        404: "not_found",
        409: "idempotency_conflict",
        429: "rate_limited",
        503: "unavailable",
      } as Record<number, string>)[response.status] ?? "request_failed";
      throw new LotorBrowserError(
        `Lotor request failed with status ${response.status}`,
        response.status,
        code,
      );
    }
    if (response.status === 204) {
      return undefined as T;
    }
    return response.json() as Promise<T>;
  }
}
