# @9in-io/sdk

Official SDK for [9in](https://9in.io). Zero dependencies; runs in browsers, Node 18+,
Cloudflare Workers, Deno and Bun.

```bash
npm install @9in-io/sdk
```

## Sign users in (browser)

```ts
import { NineAuth } from "@9in-io/sdk";

const auth = new NineAuth({
  issuer: "https://acme.9in.io",        // or your custom domain
  clientId: "app_7f3k2m9q",
  redirectUri: `${location.origin}/callback`,
  audience: "https://api.acme.com",     // optional: access tokens for your API
});

await auth.login();                      // authorization code + PKCE
await auth.signup();                     // opens the sign-up form (prompt=create)

// on /callback
const { user, returnTo } = await auth.handleRedirect();

const token = await auth.getAccessToken();   // refreshed (and rotated) automatically
const res = await auth.fetch("https://api.acme.com/orders");
await auth.logout({ returnTo: location.origin });
```

## Sign users in (server-rendered apps)

`WebAppAuth` runs the sign-in on your server: Node, Next.js (also Edge), Cloudflare Workers,
Deno and Bun. You keep the transaction (between the redirect and the callback) and the session,
for example in encrypted cookies. With Next.js, `@9in-io/nextjs` does all of that for you.

```ts
import { WebAppAuth } from "@9in-io/sdk/server";

const auth = new WebAppAuth({
  issuer: "https://acme.9in.io",
  clientId: process.env.NINE_CLIENT_ID!,
  clientSecret: process.env.NINE_CLIENT_SECRET, // confidential apps; leave out for public ones
  redirectUri: "https://app.acme.com/auth/callback",
});

// /auth/login
const { url, transaction } = await auth.createLogin({ returnTo: "/dashboard" });
// store `transaction` (encrypted, ~15 minutes), then redirect to `url`

// /auth/callback
const { tokens, claims, returnTo } = await auth.handleCallback(request.url, transaction);
// claims: the verified ID token (sub, email, name, amr…); tokens: access, refresh, ID token

const fresh = await auth.refresh(tokens.refreshToken!);  // 9in rotates refresh tokens: keep the new one
const bye = await auth.logoutUrl({ idTokenHint: tokens.idToken, postLogoutRedirectUri: "https://app.acme.com/" });
```

## Protect your API (server)

```ts
import { verifyAccessToken } from "@9in-io/sdk/server";

const claims = await verifyAccessToken(bearer, {
  issuer: "https://acme.9in.io",
  audience: "https://api.acme.com",
  scope: "orders:read",
});
```

Tokens are verified locally against your tenant's JWKS (cached; refetched once when a
new key appears after rotation). Every algorithm of the 9in key library is supported:
RS256/384/512, PS256/384/512, ES256, ES384 and EdDSA through JWKS, and HS256/384/512 when
your API uses a shared secret (`secret: process.env.NINE_API_SECRET`). The key's own
algorithm is enforced, and only access tokens (`typ: at+jwt`) are accepted.

### Revocation: hybrid verification

A local check cannot see revocations: a token revoked through `/oauth/revoke`, a sign-out
or a blocked user keeps passing until it expires. `createTokenVerifier` closes that gap:

```ts
import { createTokenVerifier, verifyWebhook } from "@9in-io/sdk/server";

const verifier = createTokenVerifier({
  issuer: "https://acme.9in.io",
  audience: "https://api.acme.com",
  clientId: process.env.NINE_CLIENT_ID,       // a confidential application
  clientSecret: process.env.NINE_CLIENT_SECRET,
  mode: "hybrid",                              // default
  cacheTtl: 300,                               // seconds an answer is trusted without news
});

const claims = await verifier.verify(bearer, { scope: "orders:read" });

// Webhook endpoint subscribed to token.revoked, session.revoked and user.* events
const event = await verifyWebhook(process.env.NINE_WEBHOOK_SECRET, request);
verifier.handleEvent(event);
```

| Mode | What it does |
|---|---|
| `local` | Signature and claims only. No calls to 9in. |
| `hybrid` | Local check, then one introspection per token. The answer is cached until a webhook says otherwise or `cacheTtl` passes; a refusal is cached until the token expires. |
| `introspect` | Introspection on every call. |

Opaque access tokens (`9in_at_…`, enabled per tenant or per API) are always introspected,
and cached in hybrid mode. The cache is in memory, per process. Each process needs the
webhook events, or a short `cacheTtl`.

## Manage users (server)

```ts
import { ManagementClient } from "@9in-io/sdk/server";

const nine = new ManagementClient({ issuer, clientId, clientSecret }); // app with management scopes
await nine.createUser({ email: "jane@acme.com", password: "…", email_verified: true });
await nine.updateUser(userId, { phone_number: "+447700900000", phone_number_verified: true });
await nine.blockUser(userId);
const { user } = await nine.findUser("phone_number", "+447700900000"); // or "email", "username"

// Sessions: list them, end one (its sid), or sign the user out everywhere
const { sessions } = await nine.listUserSessions(userId);
await nine.revokeSession(sessions[0].sid);
await nine.revokeUserSessions(userId);

// Single-use sign-in link (magic links, moving a signed-in user from your app to 9in)
const { url } = await nine.createLoginLink(userId, { returnTo: "https://app.acme.com/callback", ttlSeconds: 600 });

// Bulk import (500 per call): old ids, password hashes (bcrypt, argon2, PBKDF2, Firebase scrypt), social identities
const { results } = await nine.importUsers(
  [{ id: "auth0|42", email: "jane@acme.com", password_hash: "$2b$10$…", created_at: "2021-03-04T05:06:07Z" }],
  { onConflict: "skip", source: "auth0" },
);
```

Users, sessions and requests use snake_case field names, the same going in and coming out
(`email_verified`, `phone_number`, `password_hash`), and times are ISO 8601 UTC strings
(`created_at`, `last_login_at`). Method options stay camelCase (`returnTo`, `onConflict`).

## Keep users in your own database (adapter)

```ts
import { adapterHandler } from "@9in-io/sdk/server";

export default {
  fetch: adapterHandler({
    secret: env.NINE_ADAPTER_SECRET,
    async authenticate({ type, value }, password) {
      const user = await db.findByLogin(type, value);
      if (!user) return "invalid";
      if (user.disabled) return "blocked";
      return (await verify(password, user.hash)) ? toAdapterUser(user) : "invalid";
    },
    async findUser(query) {
      const user = "id" in query ? await db.findById(query.id) : await db.findByLogin(query.identifier.type, query.identifier.value);
      return user ? toAdapterUser(user) : null;
    },
    async onEvent(event) {
      // { id, event_type, created_at, data }; data.user_id is your own user id
      if (event.event_type === "otp.requested") await sendCode(event.data); // user_id, channel, to, code, purpose, expires_at
    },
  }),
};
```

Requests and responses are signed with HMAC-SHA256 (`9in-signature`), and each response
is bound to its request id.

## Receive webhooks (server)

Add an endpoint under **Advanced → Webhooks** in the console and keep the signing secret it
shows once. `verifyWebhook` checks the `9in-signature` header against the raw body (and a
5-minute timestamp tolerance) and returns the event, or throws `NineError` (`invalid_signature`).

```ts
import { verifyWebhook } from "@9in-io/sdk/server";

export default {
  async fetch(request: Request, env: { NINE_WEBHOOK_SECRET: string }) {
    const event = await verifyWebhook(env.NINE_WEBHOOK_SECRET, request);
    // { id, event_type, created_at, tenant, environment, data }. event.id is the same on every
    // retry and redelivery: ignore ones you have seen. data.user is the user the event is about.
    if (event.event_type === "user.created") await addToCrm(event.data.user);
    return new Response(null, { status: 204 });
  },
};
```

It reads the body, so pass `request.clone()` if you need it again. Behind a proxy that
rewrites the URL, pass the path 9in posted to: `verifyWebhook(secret, request, { path: "/hooks/9in" })`.
Several secrets (`[newSecret, oldSecret]`) are accepted while you rotate.

### Process each event once

9in retries a delivery until it gets a 2xx (for about a day), and a retry can arrive while a
slow first attempt is still running. `processEventOnce` runs your handler once per event id:

```ts
import { processEventOnce, verifyWebhook, type EventStore } from "@9in-io/sdk/server";

const event = await verifyWebhook(env.NINE_WEBHOOK_SECRET, request);
const outcome = await processEventOnce(store, event.id, () => handle(event));
// processed / duplicate → 204; in_progress → 409 (9in retries later); handler threw → id released, error rethrown (5xx)
return new Response(null, { status: outcome.status === "in_progress" ? 409 : 204 });
```

`store` is an `EventStore` whose `add` is atomic (a Durable Object, D1/SQL with a unique key,
Redis `SET NX EX`; not Workers KV). `MemoryEventStore` covers a single process. Processed ids
are kept for 3 days by default (`ttlSeconds`).

## Issuers must use https

`NineAuth`, `verifyAccessToken` and `ManagementClient` reject an issuer that is not `https://`
(`insecure_issuer`), so a typo cannot send tokens or credentials in clear text. Plain http is
accepted for `localhost`, `*.localhost` and loopback addresses; for other development hosts
(e.g. `http://auth:8897` in Docker) pass `allowInsecureIssuer: true`.

## Errors

Every failure is a `NineError` with a `code` (`login_required`, `invalid_token`,
`insufficient_scope`, `invalid_grant`, `insecure_issuer`, …) and, for HTTP errors, a `status`.
