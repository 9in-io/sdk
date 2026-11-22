# Changelog

## 0.4.0

- `createTokenVerifier({ store })`: hybrid answers and revocations shared by every instance of
  your API. The instance that receives a `token.revoked`, `session.revoked` or `user.*` webhook
  writes a revocation marker for the `jti`, `sid` or user; every instance checks those markers
  before trusting a cached answer (answers are dated when 9in was asked, allowing for clocks
  that disagree by up to `clockTolerance`). The store is the same `EventStore` interface as
  `processEventOnce`, now also exported as `Store`, with an optional `getMany` (Redis `MGET`).
  A store that can't be read means asking 9in; one that can't be written makes `handleEvent`
  reject. Without a store the in-memory cache works as before.

Breaking:

- `TokenVerifier.handleEvent` and `clear` are async: `await verifier.handleEvent(event)`, and
  answer the webhook with a 5xx when it rejects (a shared store couldn't be written).

Breaking, to match the docs and the other 9in SDKs:

- `verifyIdToken` (and `WebAppAuth.handleCallback`) throw `invalid_id_token` for every ID token
  failure, as the SDK reference says; 0.3.0 threw `invalid_token`. Access token errors stay
  `invalid_token`.
- HMAC-signed ID tokens are refused. 9in signs ID tokens with the tenant's default key, which is
  always asymmetric (an HMAC key can't be the default), so a shared secret never verified a real
  ID token. The `secret` option of `verifyIdToken` and `idTokenSecret` of `WebAppAuth` are
  removed; drop them from your code. `verifyAccessToken`'s `secret` for HMAC-signed access
  tokens is unchanged.

## 0.3.0

- `WebAppAuth` (`@9in-io/sdk/server`): sign-in for server-rendered apps (authorization code +
  PKCE, with or without a client secret), using only `fetch` and Web Crypto, so it runs on Node,
  Next.js Edge, Cloudflare Workers, Deno and Bun. `createLogin`, `handleCallback` (state, RFC 9207
  issuer check and ID token verification), `refresh`, `logoutUrl`, `revoke`, `userInfo`. It's the
  base of `@9in-io/nextjs`; you keep the transaction and session where you like.
- `verifyIdToken`: signature, issuer, audience (`azp` with several), expiry and nonce.

## 0.2.0

Breaking: 9in's wire formats are now snake_case throughout, with ISO 8601 UTC times
(see "API conventions" in the docs). Needs the 9in release of 2026-11-10.

- `WebhookEvent`: `type` → `event_type`, `createdAt` → `created_at`; `data.userId` is gone, use
  `data.user.id`. For `user.deleted`, `data.user` is the user as it was before the deletion.
  `token.revoked` data has `token_type` and `client_id`.
- `ManagedUser`: `created_at`, `updated_at`, `last_login_at` (ISO strings), `login_count`,
  and every profile field.
- `ManagedSession`: `user_id`, `auth_time`, `user_agent`, `created_at`, `last_seen_at`,
  `expires_at` (ISO strings); `revokedAt` removed.
- `getUser` returns `ManagedUserDetail` (`user`, `identities`, `sessions`, `has_password`,
  `mfa`); `listUsers` returns `next_cursor`.
- `NewUser` / `ImportUser`: `email_verified`, `phone_number`, `phone_number_verified`,
  `password_hash`, and ISO `created_at` / `last_login_at`. The server refuses the old names.
- `findUser("phone_number", …)` replaces `findUser("phone", …)`.
- `createLoginLink` returns `expires_at` as an ISO string.
- `AdapterEvent`: `event_type`, `created_at`, and `data.user_id` / `data.expires_at`.
- `TokenVerifier.handleEvent` reads the new webhook shape.
- The package ships `src/` too, so the `@9in/source` export condition resolves (0.1.x listed
  it without shipping the files, which broke bundlers configured with that condition).
