import type {
  ApplicationSession,
  AuthenticatedSession,
  CheckoutSession,
  OrganizationSummary,
  PasswordlessChallenge,
  PublicApplicationConfiguration,
  PublicApplicationPricing,
} from "./types.js";

function record(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`invalid ${name} response`);
  }
  return value as Record<string, unknown>;
}

function string(value: unknown, name: string): string {
  if (typeof value !== "string") throw new Error(`invalid ${name} response`);
  return value;
}

function number(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new Error(`invalid ${name} response`);
  return value;
}

function integer(value: unknown, name: string): number {
  const decoded = number(value, name);
  if (!Number.isSafeInteger(decoded) || decoded < 0) throw new Error(`invalid ${name} response`);
  return decoded;
}

function boolean(value: unknown, name: string): boolean {
  if (typeof value !== "boolean") throw new Error(`invalid ${name} response`);
  return value;
}

function array(value: unknown, name: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`invalid ${name} response`);
  return value;
}

export function challenge(value: unknown): PasswordlessChallenge {
  const input = record(value, "passwordless challenge");
  if (input.delivery !== "email") throw new Error("invalid passwordless delivery");
  return {
    challenge_id: string(input.challenge_id, "challenge id"),
    delivery: "email",
    expires_at: number(input.expires_at, "challenge expiry"),
  };
}

export function verification(value: unknown): { token: string; session: AuthenticatedSession } {
  const input = record(value, "passwordless verification");
  return {
    token: string(input.access_token, "access token"),
    session: {
      authenticated: true,
      subject: string(input.subject, "session subject"),
      email: string(input.email, "session email"),
    },
  };
}

export function session(value: unknown): ApplicationSession {
  const input = record(value, "session");
  if (input.authenticated !== true) throw new Error("invalid authenticated session");
  return {
    authenticated: true,
    subject: string(input.subject, "session subject"),
    email: string(input.email, "session email"),
  };
}

export function configuration(value: unknown): PublicApplicationConfiguration {
  const input = record(value, "application configuration");
  const application = record(input.application, "application");
  const environment = record(input.environment, "environment");
  const authentication = record(input.authentication, "authentication");
  return {
    clientId: string(input.client_id, "client id"),
    application: { name: string(application.name, "application name") },
    environment: {
      name: string(environment.name, "environment name"),
      isProduction: boolean(environment.is_production, "environment production flag"),
    },
    authentication: {
      methods: array(authentication.methods, "authentication methods").map((item) => string(item, "authentication method")),
    },
  };
}

export function pricing(value: unknown): PublicApplicationPricing {
  const input = record(value, "application pricing");
  return {
    clientId: string(input.client_id, "client id"),
    products: array(input.products, "pricing products").map((raw) => {
      const product = record(raw, "pricing product");
      return {
        id: string(product.id, "product id"),
        name: string(product.name, "product name"),
        ...(typeof product.description === "string" && product.description !== "" ? { description: product.description } : {}),
        type: string(product.type, "product type"),
        tier: string(product.tier, "product tier"),
        defaultCurrency: string(product.default_currency, "product default currency"),
        prices: array(product.prices, "product prices").map((item) => {
          const price = record(item, "price");
          return {
            id: string(price.id, "price id"),
            interval: string(price.interval, "price interval"),
            currency: string(price.currency, "price currency"),
            type: string(price.type, "price type"),
            unitAmount: integer(price.unit_amount, "price unit amount"),
            isDefault: boolean(price.is_default, "price default flag"),
          };
        }),
        features: array(product.features, "product features").map((item) => {
          const feature = record(item, "feature");
          return {
            id: string(feature.id, "feature id"),
            name: string(feature.name, "feature name"),
            type: string(feature.type, "feature type"),
            ...(typeof feature.unit === "string" && feature.unit !== "" ? { unit: feature.unit } : {}),
            ...(typeof feature.usage_interval === "string" && feature.usage_interval !== "" ? { usageInterval: feature.usage_interval } : {}),
            defaultMaxUnit: feature.default_max_unit === null ? null : integer(feature.default_max_unit, "feature default maximum"),
          };
        }),
      };
    }),
  };
}

export function organizations(value: unknown): OrganizationSummary[] {
  return array(value, "organizations").map((raw) => {
    const input = record(raw, "organization");
    return {
      id: string(input.id, "organization id"),
      name: string(input.name, "organization name"),
      currentRole: string(input.current_role, "organization role"),
      memberCount: integer(input.member_count, "organization member count"),
      pendingInvites: integer(input.pending_invites, "organization pending invites"),
    };
  });
}

export function checkout(value: unknown): CheckoutSession {
  const input = record(value, "checkout session");
  const id = string(input.id, "checkout session id");
  if (input.presentation === "hosted") {
    return { id, presentation: "hosted", url: string(input.url, "checkout session URL") };
  }
  if (input.presentation === "custom") {
    return {
      id,
      presentation: "custom",
      clientSecret: string(input.client_secret, "checkout client secret"),
      publishableKey: string(input.publishable_key, "checkout publishable key"),
    };
  }
  throw new Error("invalid checkout session response");
}
