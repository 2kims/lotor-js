import { BrowserTransport, LotorBrowserError, type BrowserFetch } from "./transport.js";
import * as decode from "./decode.js";
import {
  MemoryTokenStore,
  type ApplicationSession,
  type AuthenticatedSession,
  type CheckoutSession,
  type CreateCheckoutSessionInput,
  type OrganizationSummary,
  type PasswordlessChallenge,
  type PublicApplicationConfiguration,
  type PublicApplicationPricing,
  type TokenStore,
} from "./types.js";

export interface LotorBrowserOptions {
  /** Absolute Lotor public API origin, for example https://api.example.com. */
  baseUrl: string;
  clientId: string;
  tokenStore?: TokenStore;
  /** Allows HTTP only for localhost, 127.0.0.0/8, or ::1 development endpoints. */
  allowInsecureLoopback?: boolean;
  fetch?: BrowserFetch;
}

function required(value: string, name: string): string {
  const normalized = value.trim();
  if (normalized === "") throw new Error(`${name} is required`);
  return normalized;
}

function bounded(value: string, name: string, maximum = 2048): string {
  const normalized = required(value, name);
  if (normalized.length > maximum) throw new Error(`${name} is too long`);
  return normalized;
}

function publicBaseUrl(value: string, allowInsecureLoopback: boolean): string {
  let url: URL;
  try {
    url = new URL(required(value, "baseUrl"));
  } catch {
    throw new Error("baseUrl must be an absolute URL");
  }
  const loopback = url.hostname === "localhost" || url.hostname === "[::1]" || /^127(?:\.\d{1,3}){3}$/.test(url.hostname);
  if (url.protocol !== "https:" && !(allowInsecureLoopback && url.protocol === "http:" && loopback)) {
    throw new Error("baseUrl must use HTTPS; loopback HTTP requires allowInsecureLoopback");
  }
  if (url.username || url.password || url.search || url.hash || (url.pathname !== "" && url.pathname !== "/")) {
    throw new Error("baseUrl must contain only an origin");
  }
  return url.origin;
}

function safeRedirectUrl(value: string, name: string): string {
  const normalized = bounded(value, name);
  let url: URL;
  try { url = new URL(normalized); } catch { throw new Error(`${name} must be an absolute URL`); }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "[::1]" || /^127(?:\.\d{1,3}){3}$/.test(url.hostname)))) {
    throw new Error(`${name} must use HTTPS or loopback HTTP`);
  }
  return url.toString();
}

export class LotorBrowserClient {
  readonly clientId: string;
  readonly billing: { createCheckoutSession: (input: CreateCheckoutSessionInput) => Promise<CheckoutSession> };
  private readonly transport: BrowserTransport;
  private readonly tokenStore: TokenStore;
  private readonly applicationPath: string;

  constructor(options: LotorBrowserOptions) {
    this.clientId = bounded(options.clientId, "clientId", 256);
    const fetcher = options.fetch ?? globalThis.fetch?.bind(globalThis);
    if (fetcher === undefined) throw new Error("a browser Fetch implementation is required");
    this.tokenStore = options.tokenStore ?? new MemoryTokenStore();
    this.transport = new BrowserTransport(publicBaseUrl(options.baseUrl, options.allowInsecureLoopback === true), fetcher, this.tokenStore);
    this.applicationPath = `/v1/public/applications/${encodeURIComponent(this.clientId)}`;
    this.billing = { createCheckoutSession: (input) => this.createCheckoutSession(input) };
  }

  async configuration(): Promise<PublicApplicationConfiguration> {
    return decode.configuration(await this.transport.request(`${this.applicationPath}/configuration`));
  }

  async pricing(): Promise<PublicApplicationPricing> {
    return decode.pricing(await this.transport.request(`${this.applicationPath}/pricing`));
  }

  async startPasswordless(email: string): Promise<PasswordlessChallenge> {
    return decode.challenge(await this.transport.request(`${this.applicationPath}/auth/passwordless/start`, {
      method: "POST",
      body: JSON.stringify({ email: bounded(email, "email", 320) }),
    }));
  }

  async verifyPasswordless(challengeId: string, code: string): Promise<AuthenticatedSession> {
    const verified = decode.verification(await this.transport.request(`${this.applicationPath}/auth/passwordless/verify`, {
      method: "POST",
      body: JSON.stringify({
        challenge_id: bounded(challengeId, "challengeId", 256),
        code: bounded(code, "code", 64),
      }),
    }));
    await this.tokenStore.setToken(verified.token);
    return verified.session;
  }

  async session(): Promise<ApplicationSession> {
    try {
      return decode.session(await this.transport.request(`${this.applicationPath}/session`, {}, true));
    } catch (error) {
      if (error instanceof LotorBrowserError && error.status === 401) {
        await this.tokenStore.clearToken();
        return { authenticated: false };
      }
      throw error;
    }
  }

  async logout(): Promise<void> {
    try {
      await this.transport.request(`${this.applicationPath}/session`, { method: "DELETE" }, true);
    } finally {
      await this.tokenStore.clearToken();
    }
  }

  async organizations(): Promise<OrganizationSummary[]> {
    return decode.organizations(await this.transport.request(`${this.applicationPath}/organizations`, {}, true));
  }

  private async createCheckoutSession(input: CreateCheckoutSessionInput): Promise<CheckoutSession> {
    const body: Record<string, string> = {
      organization_id: bounded(input.organizationId, "organizationId", 256),
      product_id: bounded(input.productId, "productId", 256),
      price_id: bounded(input.priceId, "priceId", 256),
      presentation: input.presentation,
      idempotency_key: bounded(input.idempotencyKey, "idempotencyKey", 256),
    };
    if (input.presentation === "hosted") {
      body.success_url = safeRedirectUrl(input.successUrl, "successUrl");
      body.cancel_url = safeRedirectUrl(input.cancelUrl, "cancelUrl");
    } else {
      body.return_url = safeRedirectUrl(input.returnUrl, "returnUrl");
    }
    return decode.checkout(await this.transport.request(`${this.applicationPath}/billing/checkout-sessions`, {
      method: "POST",
      headers: { "X-Lotor-Request": "lotor-js-v1" },
      body: JSON.stringify(body),
    }, true));
  }
}
