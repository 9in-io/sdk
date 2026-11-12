# Changelog

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
