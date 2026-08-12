# @lotor.dev/lotor-js

Framework-independent, browser-only client for Lotor's public application API.
It is ESM-only, has no runtime dependencies, and never accepts a Lotor runtime
API key, Stripe secret key, or canonical tenant/application/environment ID.

The `0.1.x` line supports modern browsers with `fetch`, ESM, ES2022, TypeScript
5.7 or newer, and Node.js 22.14 or newer for development and bundling. CommonJS
is not supported.

## Authentication

```ts
import { LotorBrowserClient } from "@lotor.dev/lotor-js";

const lotor = new LotorBrowserClient({
  baseUrl: "https://api.example.lotor.dev",
  clientId: "your_public_client_id",
});

const challenge = await lotor.startPasswordless("person@example.com");
const session = await lotor.verifyPasswordless(challenge.challenge_id, "123456");
const organizations = await lotor.organizations();
```

`baseUrl` must be an absolute HTTPS origin. Loopback HTTP is available only
with `allowInsecureLoopback: true`. Requests use `credentials: "omit"` and the
application-scoped opaque bearer is attached only to protected Lotor routes.

The default `MemoryTokenStore` deliberately loses the bearer on reload. Supply
an explicit `TokenStore` when an application needs another lifecycle; the SDK
never silently writes credentials to `localStorage`.

## Checkout

Hosted and custom checkout both use the authenticated public application API.
Redirect URLs are explicit and validated before the request:

```ts
const hosted = await lotor.billing.createCheckoutSession({
  organizationId: organizations[0].id,
  productId: "product_pro",
  priceId: "price_monthly",
  presentation: "hosted",
  successUrl: `${location.origin}/usage`,
  cancelUrl: `${location.origin}/pricing`,
  idempotencyKey: crypto.randomUUID(),
});

if (hosted.presentation === "hosted") location.assign(hosted.url);
```

Custom Checkout returns only Stripe's browser-facing publishable key and client
secret. Provider credentials and webhook secrets stay in Lotor.

## Public reads and session lifecycle

- `configuration()` reads the secret-safe public Auth configuration.
- `pricing()` reads published products, prices, and features.
- `session()` validates the stored bearer and maps an absent, expired, or
  revoked token to `{ authenticated: false }`.
- `organizations()` lists only organizations available to the current subject.
- `logout()` revokes the current bearer and always clears the token store.

Invitation and member management are intentionally not part of this browser
surface. Those operations depend on an application's runtime and authorization
model and belong behind that application's authenticated API.

## Security

Never place a Lotor runtime API key, Stripe secret key, provider webhook secret,
or application backend credential in browser code. Report vulnerabilities
privately through the repository's security advisory form instead of opening a
public issue.

## Development

Install the frozen dependency graph and run the release checks:

```bash
pnpm install --frozen-lockfile
pnpm check:browser
pnpm test
pnpm api:check
pnpm package:check
pnpm test:tooling
pnpm verify:workflows
```

Releases use conventional squash-merged PR titles, Release Please, and npm trusted publishing. See [RELEASING.md](RELEASING.md) for setup, recovery, and shutdown procedures.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
