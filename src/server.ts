import { NineError, decodeJwt, discover, normalizeIssuer, postForm, toHex, utf8 } from "./util.js";

export { NineError, normalizeIssuer } from "./util.js";
export { WebAppAuth, type WebAppAuthOptions, type WebLoginOptions, type LoginTransaction, type WebTokenSet, type CallbackResult } from "./web-app.js";

// ---------------------------------------------------------------------------
// Access token verification

export interface VerifyOptions {
  /** Your tenant's issuer (exactly as in the token's iss claim). */
  issuer: string;
  /** API identifier the token must be issued for (aud). */
  audience?: string | string[];
  /** Scopes that must all be present (space-separated or array). */
  scope?: string | string[];
  /**
   * Shared secret of the HMAC key (HS256/384/512) your API signs with, from the console's
   * key library. Only needed when the API uses an HMAC key; JWKS keys need nothing.
   */
  secret?: string;
  /** Allowed clock skew in seconds (default 30). */
  clockTolerance?: number;
  /** Accept a plain-http issuer other than localhost (development only). */
  allowInsecureIssuer?: boolean;
  fetch?: typeof fetch;
}

export interface AccessTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  client_id: string;
  scope: string;
  jti?: string;
  sid?: string;
  auth_time?: number;
  [claim: string]: unknown;
}

interface Jwk extends JsonWebKey {
  kid?: string;
  alg?: string;
  crv?: string;
  x?: string;
}

// Derived from SubtleCrypto itself so the SDK type-checks under DOM, Node and Workers typings.
type SubtleParams = { import: Parameters<SubtleCrypto["importKey"]>[2]; verify: Parameters<SubtleCrypto["verify"]>[0] };

/** WebCrypto parameters for each JWS algorithm 9in signs with. */
const ALGORITHMS: Record<string, SubtleParams> = {
  RS256: { import: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, verify: "RSASSA-PKCS1-v1_5" },
  RS384: { import: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" }, verify: "RSASSA-PKCS1-v1_5" },
  RS512: { import: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" }, verify: "RSASSA-PKCS1-v1_5" },
  PS256: { import: { name: "RSA-PSS", hash: "SHA-256" }, verify: { name: "RSA-PSS", saltLength: 32 } },
  PS384: { import: { name: "RSA-PSS", hash: "SHA-384" }, verify: { name: "RSA-PSS", saltLength: 48 } },
  PS512: { import: { name: "RSA-PSS", hash: "SHA-512" }, verify: { name: "RSA-PSS", saltLength: 64 } },
  ES256: { import: { name: "ECDSA", namedCurve: "P-256" }, verify: { name: "ECDSA", hash: "SHA-256" } },
  ES384: { import: { name: "ECDSA", namedCurve: "P-384" }, verify: { name: "ECDSA", hash: "SHA-384" } },
  EdDSA: { import: { name: "Ed25519" }, verify: "Ed25519" },
};
const HMAC_HASH: Record<string, string> = { HS256: "SHA-256", HS384: "SHA-384", HS512: "SHA-512" };

const jwksCache = new Map<string, { keys: Jwk[]; fetchedAt: number }>();
const keyCache = new Map<string, CryptoKey>();
/**
 * kid → time it was last looked up without success. An unknown kid (e.g. right after a key
 * rotation) triggers one JWKS refetch; junk kids are then ignored for a minute.
 */
const missingKids = new Map<string, number>();

async function jwks(issuer: string, fetcher: typeof fetch, force = false): Promise<Jwk[]> {
  const hit = jwksCache.get(issuer);
  if (hit && !force && Date.now() - hit.fetchedAt < 10 * 60_000) return hit.keys;
  const config = await discover(issuer, fetcher);
  const res = await fetcher(config.jwks_uri);
  if (!res.ok) throw new NineError("jwks_unavailable", `HTTP ${res.status}`, res.status);
  const body = (await res.json()) as { keys: Jwk[] };
  jwksCache.set(issuer, { keys: body.keys, fetchedAt: Date.now() });
  return body.keys;
}

async function findKey(issuer: string, kid: unknown, fetcher: typeof fetch): Promise<Jwk | undefined> {
  const keys = await jwks(issuer, fetcher);
  const known = keys.find((k) => k.kid === kid);
  if (known) return known;
  const missKey = `${issuer}|${String(kid)}`;
  const missedAt = missingKids.get(missKey);
  if (missedAt && Date.now() - missedAt < 60_000) return undefined;
  const refreshed = (await jwks(issuer, fetcher, true)).find((k) => k.kid === kid);
  if (!refreshed) {
    missingKids.set(missKey, Date.now());
    if (missingKids.size > 1000) missingKids.clear();
  }
  return refreshed;
}

async function importPublicKey(jwk: Jwk, alg: string): Promise<CryptoKey> {
  const id = `${alg}:${jwk.kid}:${(jwk.n ?? jwk.x ?? "").slice(0, 32)}`;
  let key = keyCache.get(id);
  if (!key) {
    const { kty, n, e, crv, x, y } = jwk;
    const material = kty === "RSA" ? { kty, n, e } : kty === "EC" ? { kty, crv, x, y } : { kty, crv, x };
    key = await crypto.subtle.importKey("jwk", material, ALGORITHMS[alg]!.import, false, ["verify"]);
    if (keyCache.size > 200) keyCache.clear();
    keyCache.set(id, key);
  }
  return key;
}

const ACCESS_TOKEN_TYPES = new Set(["at+jwt", "application/at+jwt"]);

/**
 * Verifies a 9in JWT access token locally: signature (against your tenant's JWKS, or your
 * API's shared secret for HMAC keys), token type, issuer, audience, expiry and required
 * scopes. Keys are cached and refetched once when a new key appears.
 *
 * This is a local check: a token revoked before it expires still passes. Use
 * `createTokenVerifier` (hybrid mode) when revocation must take effect at once.
 */
export async function verifyAccessToken(token: string | null | undefined, options: VerifyOptions): Promise<AccessTokenClaims> {
  if (!token) throw new NineError("invalid_token", "missing token", 401);
  const fetcher = options.fetch ?? fetch.bind(globalThis);
  const issuer = normalizeIssuer(options.issuer, options.allowInsecureIssuer);
  let parts;
  try {
    parts = decodeJwt(token);
  } catch {
    throw new NineError("invalid_token", "malformed token", 401);
  }
  const { header, payload, signingInput, signature } = parts;
  const alg = String(header.alg);
  if (!ACCESS_TOKEN_TYPES.has(String(header.typ).toLowerCase())) throw new NineError("invalid_token", "not an access token", 401);
  let valid: boolean;
  if (HMAC_HASH[alg]) {
    if (!options.secret) throw new NineError("invalid_token", "HMAC-signed token: pass the API's secret", 401);
    const key = await crypto.subtle.importKey("raw", utf8(options.secret), { name: "HMAC", hash: HMAC_HASH[alg] }, false, ["verify"]);
    valid = await crypto.subtle.verify("HMAC", key, signature, utf8(signingInput));
  } else if (ALGORITHMS[alg]) {
    const jwk = await findKey(issuer, header.kid, fetcher);
    if (!jwk) throw new NineError("invalid_token", "unknown signing key", 401);
    // The key decides the algorithm, never the token alone (no algorithm confusion).
    if (jwk.alg && jwk.alg !== alg) throw new NineError("invalid_token", "algorithm does not match the key", 401);
    valid = await crypto.subtle.verify(ALGORITHMS[alg]!.verify, await importPublicKey(jwk, alg), signature, utf8(signingInput));
  } else {
    throw new NineError("invalid_token", "unsupported algorithm", 401);
  }
  if (!valid) throw new NineError("invalid_token", "bad signature", 401);
  checkClaims(payload, issuer, options);
  return payload as AccessTokenClaims;
}

export interface VerifyIdTokenOptions {
  /** Your tenant's issuer URL. */
  issuer: string;
  /** Your application's client ID (the token's audience). */
  clientId: string;
  /** The nonce sent with the sign-in request. */
  nonce?: string | null;
  /** For tenants whose signing key is a shared (HMAC) secret. */
  secret?: string;
  /** Seconds of clock skew allowed (default 30). */
  clockTolerance?: number;
  fetch?: typeof fetch;
  allowInsecureIssuer?: boolean;
}

/** Claims of a verified ID token (standard OIDC claims plus your custom profile claims). */
export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  nonce?: string;
  auth_time?: number;
  /** How the user signed in, e.g. ["pwd", "mfa", "otp"]. */
  amr?: string[];
  sid?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  picture?: string;
  [claim: string]: unknown;
}

/**
 * Verifies an ID token from your tenant: signature (JWKS, or the shared secret for HMAC keys),
 * issuer, audience (your client ID; `azp` when there are several), expiry and nonce.
 */
export async function verifyIdToken(token: string | null | undefined, options: VerifyIdTokenOptions): Promise<IdTokenClaims> {
  if (!token) throw new NineError("invalid_token", "missing ID token", 401);
  const fetcher = options.fetch ?? fetch.bind(globalThis);
  const issuer = normalizeIssuer(options.issuer, options.allowInsecureIssuer);
  let parts;
  try {
    parts = decodeJwt(token);
  } catch {
    throw new NineError("invalid_token", "malformed ID token", 401);
  }
  const { header, payload, signingInput, signature } = parts;
  const alg = String(header.alg);
  // An access token is never accepted as an ID token.
  if (ACCESS_TOKEN_TYPES.has(String(header.typ ?? "").toLowerCase())) throw new NineError("invalid_token", "not an ID token", 401);
  let valid: boolean;
  if (HMAC_HASH[alg]) {
    if (!options.secret) throw new NineError("invalid_token", "HMAC-signed ID token: pass the tenant's shared secret", 401);
    const key = await crypto.subtle.importKey("raw", utf8(options.secret), { name: "HMAC", hash: HMAC_HASH[alg] }, false, ["verify"]);
    valid = await crypto.subtle.verify("HMAC", key, signature, utf8(signingInput));
  } else if (ALGORITHMS[alg]) {
    const jwk = await findKey(issuer, header.kid, fetcher);
    if (!jwk) throw new NineError("invalid_token", "unknown signing key", 401);
    if (jwk.alg && jwk.alg !== alg) throw new NineError("invalid_token", "algorithm does not match the key", 401);
    valid = await crypto.subtle.verify(ALGORITHMS[alg]!.verify, await importPublicKey(jwk, alg), signature, utf8(signingInput));
  } else {
    throw new NineError("invalid_token", "unsupported algorithm", 401);
  }
  if (!valid) throw new NineError("invalid_token", "bad signature", 401);
  checkClaims(payload, issuer, { issuer, audience: options.clientId, clockTolerance: options.clockTolerance });
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (aud.length > 1 && payload.azp !== options.clientId) throw new NineError("invalid_token", "authorized party mismatch", 401);
  if (options.nonce !== undefined && options.nonce !== null && payload.nonce !== options.nonce) throw new NineError("invalid_token", "nonce mismatch", 401);
  if (typeof payload.sub !== "string" || !payload.sub) throw new NineError("invalid_token", "missing subject", 401);
  return payload as IdTokenClaims;
}

function checkClaims(payload: Record<string, unknown>, issuer: string, options: VerifyOptions): void {
  const now = Math.floor(Date.now() / 1000);
  const skew = options.clockTolerance ?? 30;
  if (String(payload.iss).replace(/\/$/, "") !== issuer) throw new NineError("invalid_token", "issuer mismatch", 401);
  if (typeof payload.exp !== "number" || payload.exp + skew < now) throw new NineError("invalid_token", "token expired", 401);
  if (typeof payload.nbf === "number" && payload.nbf - skew > now) throw new NineError("invalid_token", "token not yet valid", 401);
  if (options.audience) {
    const wanted = Array.isArray(options.audience) ? options.audience : [options.audience];
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!wanted.some((a) => aud.includes(a))) throw new NineError("invalid_token", "audience mismatch", 401);
  }
  checkScope(payload, options.scope);
}

function checkScope(payload: Record<string, unknown>, scope: string | string[] | undefined): void {
  if (!scope) return;
  const required = Array.isArray(scope) ? scope : scope.split(" ").filter(Boolean);
  const granted = new Set(String(payload.scope ?? "").split(" "));
  const missing = required.filter((s) => !granted.has(s));
  if (missing.length) throw new NineError("insufficient_scope", `missing ${missing.join(", ")}`, 403);
}

// ---------------------------------------------------------------------------
// Hybrid verification (revocation that takes effect at once)

export type VerificationMode = "local" | "hybrid" | "introspect";

export interface TokenVerifierOptions extends Omit<VerifyOptions, "scope"> {
  /**
   * - `hybrid` (default): the local check, then one introspection per token; the answer is
   *   cached and dropped when a `token.revoked`, `session.revoked` or user webhook arrives
   *   (pass events to `handleEvent`), or after `cacheTtl` at the latest.
   * - `local`: signature and claims only. Fastest; a revoked token works until it expires.
   * - `introspect`: ask 9in on every call. Always current; one request per call.
   * Opaque tokens (`9in_at_…`) are always introspected (and cached in hybrid mode).
   */
  mode?: VerificationMode;
  /** A confidential application's credentials, used for introspection. */
  clientId?: string;
  clientSecret?: string;
  /** Longest time a hybrid answer is trusted without hearing from 9in, in seconds (default 300). */
  cacheTtl?: number;
  /** Most tokens kept in the cache (default 10 000; the least recently used go first). */
  cacheSize?: number;
}

interface CacheEntry {
  claims: AccessTokenClaims | null;
  /** ms */
  until: number;
}

export interface TokenVerifier {
  /** Verifies a bearer token (JWT or opaque) and returns its claims, or throws `NineError`. */
  verify(token: string | null | undefined, options?: { scope?: string | string[] }): Promise<AccessTokenClaims>;
  /**
   * Drops cached answers a webhook event makes stale; returns how many. Pass events from
   * `verifyWebhook` (subscribe the endpoint to token.revoked, session.revoked,
   * user.sessions_revoked, user.updated and user.deleted).
   */
  handleEvent(event: { event_type: string; data: Record<string, unknown> }): number;
  /** Forgets every cached answer. */
  clear(): void;
}

const OPAQUE_PREFIX = "9in_at_";

async function cacheKey(token: string): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(token))));
}

/**
 * Token verification with a choice of trade-off between speed and revocation (SSOfy's
 * "hybrid" validation, kept): see `mode`.
 *
 *   const verifier = createTokenVerifier({ issuer, audience: "https://api.acme.com", clientId, clientSecret });
 *   const claims = await verifier.verify(bearer, { scope: "orders:read" });
 *
 *   // webhook endpoint (token.revoked, session.revoked, user.* events)
 *   verifier.handleEvent(await verifyWebhook(secret, request));
 */
export function createTokenVerifier(options: TokenVerifierOptions): TokenVerifier {
  const mode = options.mode ?? "hybrid";
  const fetcher = options.fetch ?? fetch.bind(globalThis);
  const issuer = normalizeIssuer(options.issuer, options.allowInsecureIssuer);
  const ttl = (options.cacheTtl ?? 300) * 1000;
  const size = options.cacheSize ?? 10_000;
  const cache = new Map<string, CacheEntry>();
  const inflight = new Map<string, Promise<AccessTokenClaims | null>>();

  if (mode !== "local" && (!options.clientId || !options.clientSecret)) {
    throw new NineError("invalid_options", `${mode} mode needs clientId and clientSecret (a confidential application) for introspection`);
  }

  async function introspect(token: string): Promise<AccessTokenClaims | null> {
    const config = await discover(issuer, fetcher);
    const endpoint = config.introspection_endpoint ?? `${issuer}/oauth/introspect`;
    const body = await postForm<Record<string, unknown>>(
      endpoint,
      { token },
      { Authorization: `Basic ${btoa(`${encodeURIComponent(options.clientId!)}:${encodeURIComponent(options.clientSecret!)}`)}` },
      fetcher,
    );
    if (body.active !== true || body.token_type === "refresh_token") return null;
    return body as unknown as AccessTokenClaims;
  }

  function remember(key: string, entry: CacheEntry) {
    cache.delete(key);
    cache.set(key, entry);
    while (cache.size > size) cache.delete(cache.keys().next().value!);
  }

  /** The live claims (`local` for a JWT, once 9in confirms it is active), or null when revoked. */
  async function lookup(token: string, local: AccessTokenClaims | null): Promise<AccessTokenClaims | null> {
    const key = await cacheKey(token);
    if (mode === "hybrid") {
      const hit = cache.get(key);
      if (hit && hit.until > Date.now()) {
        remember(key, hit); // most recently used
        return hit.claims;
      }
    }
    let pending = inflight.get(key);
    if (!pending) {
      pending = introspect(token).finally(() => inflight.delete(key));
      inflight.set(key, pending);
    }
    const answer = await pending;
    const claims = answer && local ? local : answer;
    if (mode === "hybrid") {
      const expiry = (claims?.exp ?? local?.exp ?? 0) * 1000;
      // A revoked token never comes back: remember the refusal until it expires.
      const until = claims ? Math.min(Date.now() + ttl, expiry) : expiry ? expiry : Date.now() + 60_000;
      if (until > Date.now()) remember(key, { claims, until });
    }
    return claims;
  }

  return {
    async verify(token, extra = {}) {
      if (!token) throw new NineError("invalid_token", "missing token", 401);
      const opaque = token.startsWith(OPAQUE_PREFIX);
      if (opaque && mode === "local") throw new NineError("invalid_token", "opaque tokens need hybrid or introspect mode", 401);
      const local = opaque ? null : await verifyAccessToken(token, { ...options, scope: extra.scope });
      if (mode === "local") return local!;
      const claims = await lookup(token, local);
      if (!claims) throw new NineError("invalid_token", "token revoked", 401);
      if (!local) checkClaims(claims, issuer, { ...options, scope: extra.scope });
      return claims;
    },

    handleEvent(event) {
      const data = event.data ?? {};
      const userId = (data.user as { id?: unknown } | null | undefined)?.id;
      let match: ((claims: AccessTokenClaims) => boolean) | null = null;
      if (event.event_type === "token.revoked" && data.token_type === "access_token" && data.jti) match = (c) => c.jti === data.jti;
      else if (event.event_type === "session.revoked" && data.sid) match = (c) => c.sid === data.sid;
      else if (["user.sessions_revoked", "user.deleted", "user.updated", "user.password_changed"].includes(event.event_type) && typeof userId === "string") {
        match = (c) => c.sub === userId;
      }
      if (!match) return 0;
      let evicted = 0;
      for (const [key, entry] of cache) {
        if (entry.claims && match(entry.claims)) {
          cache.delete(key);
          evicted++;
        }
      }
      return evicted;
    },

    clear() {
      cache.clear();
    },
  };
}

// ---------------------------------------------------------------------------
// Management API

export interface ManagementOptions {
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** Accept a plain-http issuer other than localhost (development only). */
  allowInsecureIssuer?: boolean;
  fetch?: typeof fetch;
}

/** A user as the Management API and webhooks send it. Times are ISO 8601 UTC strings. */
export interface ManagedUser {
  id: string;
  email: string | null;
  email_verified: boolean;
  phone_number: string | null;
  phone_number_verified: boolean;
  username: string | null;
  preferred_username: string | null;
  name: string | null;
  given_name: string | null;
  middle_name: string | null;
  family_name: string | null;
  nickname: string | null;
  gender: string | null;
  website: string | null;
  picture: string | null;
  locale: string | null;
  zoneinfo: string | null;
  birthdate: string | null;
  blocked: boolean;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  last_login_at: string | null;
  login_count: number;
}

/** An active sign-in session (`sid` is the `sid` claim of its tokens). Times are ISO 8601 UTC strings. */
export interface ManagedSession {
  sid: string;
  user_id: string;
  auth_time: string;
  amr: string[];
  ip: string;
  user_agent: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
}

/** A linked sign-in of a user (`social:google`, `enterprise:<id>`, `adapter`, …). */
export interface ManagedIdentity {
  connection: string;
  subject: string;
  profile: Record<string, unknown>;
  created_at: string;
}

/** `getUser`: the user with their identities, active sessions and two-factor state. */
export interface ManagedUserDetail {
  user: ManagedUser;
  identities: ManagedIdentity[];
  sessions: ManagedSession[];
  has_password: boolean;
  mfa: { enabled: boolean; enabled_at?: string; recovery_codes_left?: number };
}

/** One record for `importUsers`: the fields of `createUser` plus what an import may carry over. */
export interface ImportUser {
  /** Keep the id from your old system (letters, digits and | _ . : @ + -, max 128). */
  id?: string;
  email?: string | null;
  email_verified?: boolean;
  /** E.164, e.g. +447700900000. */
  phone_number?: string | null;
  phone_number_verified?: boolean;
  username?: string | null;
  name?: string | null;
  given_name?: string | null;
  family_name?: string | null;
  picture?: string | null;
  locale?: string | null;
  zoneinfo?: string | null;
  birthdate?: string | null;
  metadata?: Record<string, unknown>;
  blocked?: boolean;
  /** A plain password (at most 50 such records per call), or `password_hash` from your old system. */
  password?: string;
  /** bcrypt, argon2, PBKDF2 or Firebase scrypt hash: users keep their password. */
  password_hash?: string;
  /** Linked sign-ins, e.g. { connection: "social:google", subject: "1069…" }. */
  identities?: { connection: string; subject: string }[];
  /** Original dates, ISO 8601 (`Z` or an offset). */
  created_at?: string;
  last_login_at?: string;
}

/** Fields of a new user (`createUser`); `updateUser` takes any of them. */
export type NewUser = Omit<ImportUser, "id" | "identities" | "created_at" | "last_login_at">;

export type ImportResult = { index: number; ok: boolean } & (
  | { status: "created" | "updated"; id: string }
  | { status: "skipped"; id: string; reason: string }
  | { status: "failed"; error: string; details?: unknown }
);

/** Users and sessions of one tenant environment, with a client-credentials token. */
type ManagementScope = "management:users:read" | "management:users:write" | "management:sessions:write";

export class ManagementClient {
  /** One token per scope: each call asks only for what it needs, so an app granted some scopes works. */
  private readonly tokens = new Map<ManagementScope, { value: string; expiresAt: number }>();
  private readonly fetcher: typeof fetch;
  private readonly issuer: string;

  constructor(private readonly options: ManagementOptions) {
    this.fetcher = options.fetch ?? fetch.bind(globalThis);
    this.issuer = normalizeIssuer(options.issuer, options.allowInsecureIssuer);
  }

  private async accessToken(scope: ManagementScope): Promise<string> {
    const cached = this.tokens.get(scope);
    if (cached && cached.expiresAt - 30_000 > Date.now()) return cached.value;
    const config = await discover(this.issuer, this.fetcher);
    const result = await postForm<{ access_token: string; expires_in: number }>(
      config.token_endpoint,
      { grant_type: "client_credentials", scope },
      { Authorization: `Basic ${btoa(`${encodeURIComponent(this.options.clientId)}:${encodeURIComponent(this.options.clientSecret)}`)}` },
      this.fetcher,
    );
    this.tokens.set(scope, { value: result.access_token, expiresAt: Date.now() + result.expires_in * 1000 });
    return result.access_token;
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const scope: ManagementScope = method === "GET" ? "management:users:read" : path.includes("/sessions") ? "management:sessions:write" : "management:users:write";
    const res = await this.fetcher(`${this.issuer}/api/v1${path}`, {
      method,
      headers: { Authorization: `Bearer ${await this.accessToken(scope)}`, Accept: "application/json", ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (res.status === 204) return undefined as T;
    const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) throw new NineError(String(json.error ?? "request_failed"), json.error_description ? String(json.error_description) : `HTTP ${res.status}`, res.status);
    return json as T;
  }

  listUsers(options: { query?: string; cursor?: string; limit?: number } = {}) {
    const params = new URLSearchParams();
    if (options.query) params.set("q", options.query);
    if (options.cursor) params.set("cursor", options.cursor);
    if (options.limit) params.set("limit", String(options.limit));
    return this.request<{ users: ManagedUser[]; next_cursor: string | null; total: number }>("GET", `/users?${params}`);
  }

  /** The user with their identities, active sessions and two-factor state. */
  getUser(id: string) {
    return this.request<ManagedUserDetail>("GET", `/users/${encodeURIComponent(id)}`);
  }

  findUserByEmail(email: string) {
    return this.findUser("email", email);
  }

  /** Looks a user up by email, phone number (E.164) or username; throws `not_found` (404) when unknown. */
  findUser(type: "email" | "phone_number" | "username", value: string) {
    return this.request<{ user: ManagedUser }>("GET", `/users/lookup?${type}=${encodeURIComponent(value)}`);
  }

  createUser(input: NewUser) {
    return this.request<{ user: ManagedUser }>("POST", "/users", input);
  }

  /**
   * Bulk import, up to 500 users per call. Records may keep their old id and carry password
   * hashes (bcrypt, argon2, PBKDF2, Firebase scrypt), social identities and original dates.
   * Results are per record, in order; one bad record does not stop the others.
   */
  importUsers(users: ImportUser[], options: { onConflict?: "skip" | "update"; source?: string } = {}) {
    return this.request<{ results: ImportResult[] }>("POST", "/users/import", {
      users,
      ...(options.onConflict ? { on_conflict: options.onConflict } : {}),
      ...(options.source ? { source: options.source } : {}),
    });
  }

  /** Changes only the fields you send; `metadata` is replaced as a whole. */
  updateUser(id: string, input: Partial<NewUser>) {
    return this.request<{ user: ManagedUser }>("PATCH", `/users/${encodeURIComponent(id)}`, input);
  }

  deleteUser(id: string) {
    return this.request<void>("DELETE", `/users/${encodeURIComponent(id)}`);
  }

  blockUser(id: string, blocked = true) {
    return this.updateUser(id, { blocked });
  }

  /**
   * Single-use URL that signs the user in (magic links, handing a user over from your app).
   * `returnTo` must be a registered redirect URL of one of your applications or a path on
   * the login domain. Two-factor authentication still applies.
   */
  createLoginLink(id: string, options: { returnTo?: string; ttlSeconds?: number } = {}) {
    return this.request<{ url: string; expires_at: string }>("POST", `/users/${encodeURIComponent(id)}/login-link`, {
      ...(options.returnTo ? { return_to: options.returnTo } : {}),
      ...(options.ttlSeconds ? { ttl_seconds: options.ttlSeconds } : {}),
    });
  }

  /** The user's active sessions, most recently used first. */
  listUserSessions(id: string) {
    return this.request<{ sessions: ManagedSession[] }>("GET", `/users/${encodeURIComponent(id)}/sessions`);
  }

  /** Signs the user out everywhere; returns how many sessions ended. */
  revokeUserSessions(id: string) {
    return this.request<{ revoked: number }>("DELETE", `/users/${encodeURIComponent(id)}/sessions`);
  }

  /** Ends one session (its `sid`) and every token issued under it. */
  revokeSession(sid: string) {
    return this.request<void>("DELETE", `/sessions/${encodeURIComponent(sid)}`);
  }
}

// ---------------------------------------------------------------------------
// Adapter protocol (keep users in your own database)

export interface AdapterIdentifier {
  type: "email" | "username" | "phone";
  value: string;
}

export interface AdapterUser {
  id: string;
  email?: string | null;
  email_verified?: boolean | null;
  phone_number?: string | null;
  phone_number_verified?: boolean | null;
  username?: string | null;
  name?: string | null;
  given_name?: string | null;
  family_name?: string | null;
  picture?: string | null;
  locale?: string | null;
  zoneinfo?: string | null;
  birthdate?: string | null;
  blocked?: boolean | null;
  metadata?: Record<string, unknown> | null;
}

/**
 * What 9in POSTs to `…/event`. `data.user_id` is your own user id. `otp.requested` carries
 * `user_id, channel, to, code, purpose, expires_at`; `user.updated` and
 * `user.password_changed` carry `user_id, fields`.
 */
export interface AdapterEvent {
  id: string;
  event_type: "otp.requested" | "user.created" | "user.updated" | "user.password_changed" | "session.revoked";
  /** ISO 8601 UTC. */
  created_at: string;
  data: { user_id?: string; [field: string]: unknown };
}

export interface AdapterHandlers {
  /** Shared secret from the console (Connections → User database). Several allow rotation. */
  secret: string | string[];
  /** Check a password. Return the user, "invalid" or "blocked". */
  authenticate(identifier: AdapterIdentifier, password: string): Promise<AdapterUser | "invalid" | "blocked">;
  /** Look a user up by identifier or id; null when unknown. */
  findUser(query: { identifier: AdapterIdentifier } | { id: string }): Promise<AdapterUser | null>;
  /** Notifications, including `otp.requested` when you deliver codes yourself. */
  onEvent?(event: AdapterEvent): Promise<void>;
  /** Signature tolerance in seconds (default 300). */
  toleranceSeconds?: number;
}

const SIGNATURE_HEADER = "9in-signature";

async function hmac(secret: string, payload: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", utf8(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toHex(new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8(payload))));
}

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Verifies a `9in-signature` header: t=<unix>,v1=<hex HMAC(t.METHOD.path.body)>. */
export async function verifySignature(secret: string | string[], header: string | null, method: string, path: string, body: string, toleranceSeconds = 300): Promise<boolean> {
  if (!header) return false;
  const parts = header.split(",").map((p) => p.trim());
  const t = Number(parts.find((p) => p.startsWith("t="))?.slice(2));
  const signatures = parts.filter((p) => p.startsWith("v1=")).map((p) => p.slice(3));
  if (!Number.isFinite(t) || Math.abs(Date.now() / 1000 - t) > toleranceSeconds || !signatures.length) return false;
  for (const s of Array.isArray(secret) ? secret : [secret]) {
    const expected = await hmac(s, `${t}.${method.toUpperCase()}.${path}.${body}`);
    if (signatures.some((sig) => safeEqual(sig, expected))) return true;
  }
  return false;
}

export async function signPayload(secret: string, method: string, path: string, body: string): Promise<string> {
  const t = Math.floor(Date.now() / 1000);
  return `t=${t},v1=${await hmac(secret, `${t}.${method.toUpperCase()}.${path}.${body}`)}`;
}

// ---------------------------------------------------------------------------
// Webhooks

export type WebhookEventType =
  | "user.created"
  | "user.updated"
  | "user.deleted"
  | "user.login"
  | "user.login_failed"
  | "user.password_changed"
  | "user.mfa_enabled"
  | "user.mfa_disabled"
  | "user.sessions_revoked"
  | "session.revoked"
  | "token.revoked"
  | "webhook.test";

export interface WebhookEvent<Data extends Record<string, unknown> = Record<string, unknown>> {
  /** Event id: the same on every retry and redelivery, so you can ignore duplicates. */
  id: string;
  /** The event name, also in the `9in-event-type` header. */
  event_type: WebhookEventType;
  /** ISO 8601 UTC. */
  created_at: string;
  /** Tenant id (tnt_…). */
  tenant: string;
  environment: "production" | "sandbox";
  /**
   * Event details, plus the `user` the event is about (null when there is none; for
   * `user.deleted`, the user as it was just before the deletion).
   */
  data: Data & { user?: ManagedUser | null };
}

export interface VerifyWebhookOptions {
  /** Signature tolerance in seconds (default 300). */
  toleranceSeconds?: number;
  /** The path 9in posted to, when a proxy or framework rewrote `request.url` (default: its pathname). */
  path?: string;
}

/**
 * Verifies a webhook request from 9in (the `9in-signature` header over the raw body) and
 * returns the parsed event. Throws `NineError` (`invalid_signature`, 401) otherwise. Reads
 * the body, so pass `request.clone()` if you need it afterwards.
 *
 *   const event = await verifyWebhook(env.NINE_WEBHOOK_SECRET, request);
 *   if (event.event_type === "user.created") …
 */
export async function verifyWebhook(secret: string | string[], request: Request, options: VerifyWebhookOptions = {}): Promise<WebhookEvent> {
  const body = await request.text();
  const path = options.path ?? new URL(request.url).pathname;
  const valid =
    request.method.toUpperCase() === "POST" &&
    (await verifySignature(secret, request.headers.get(SIGNATURE_HEADER), "POST", path, body, options.toleranceSeconds));
  if (!valid) throw new NineError("invalid_signature", "webhook signature verification failed", 401);
  try {
    return JSON.parse(body) as WebhookEvent;
  } catch {
    throw new NineError("invalid_payload", "webhook body is not JSON", 400);
  }
}

// ---------------------------------------------------------------------------
// Processing each event once

/**
 * Key-value store for `processEventOnce`. `add` must be atomic (insert only when the key is
 * absent or expired): use a Durable Object, D1/SQL with a unique key, or Redis `SET NX EX`.
 * Workers KV is eventually consistent and not suitable.
 */
export interface EventStore {
  add(key: string, value: string, ttlSeconds: number): Promise<boolean>;
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlSeconds: number): Promise<void>;
  delete(key: string): Promise<void>;
}

/** In-memory EventStore: one process only (tests, single-instance servers). */
export class MemoryEventStore implements EventStore {
  private readonly items = new Map<string, { value: string; expiresAt: number }>();

  private live(key: string) {
    const item = this.items.get(key);
    if (item && item.expiresAt <= Date.now()) {
      this.items.delete(key);
      return undefined;
    }
    return item;
  }

  async add(key: string, value: string, ttlSeconds: number): Promise<boolean> {
    if (this.live(key)) return false;
    this.items.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
    if (this.items.size > 10_000) for (const k of this.items.keys()) this.live(k);
    return true;
  }

  async get(key: string): Promise<string | null> {
    return this.live(key)?.value ?? null;
  }

  async set(key: string, value: string, ttlSeconds: number): Promise<void> {
    this.items.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
  }

  async delete(key: string): Promise<void> {
    this.items.delete(key);
  }
}

export interface ProcessOnceOptions {
  /** How long a processed id is remembered (default 3 days; 9in retries for about a day). */
  ttlSeconds?: number;
  /** How long a running handler holds the id before another delivery may take over (default 300). */
  lockSeconds?: number;
  /** Key prefix (default "9in:event:"). */
  prefix?: string;
}

export type ProcessOnceResult<T> = { status: "processed"; result: T } | { status: "duplicate" } | { status: "in_progress" };

/**
 * Runs `handler` at most once per event id. 9in keeps the id on every retry and redelivery.
 *
 * - `processed`: first delivery, handler succeeded → answer 2xx.
 * - `duplicate`: already processed → answer 2xx so 9in stops retrying.
 * - `in_progress`: another delivery of the same event is still running → answer 409 so
 *   9in tries again later.
 * - The handler threw: the id is released and the error rethrown → answer 5xx so 9in retries.
 *
 *   const event = await verifyWebhook(secret, request);
 *   const outcome = await processEventOnce(store, event.id, () => handle(event));
 *   return new Response(null, { status: outcome.status === "in_progress" ? 409 : 204 });
 */
export async function processEventOnce<T>(store: EventStore, eventId: string, handler: () => T | Promise<T>, options: ProcessOnceOptions = {}): Promise<ProcessOnceResult<T>> {
  if (!eventId) throw new NineError("invalid_event", "event id required");
  const key = `${options.prefix ?? "9in:event:"}${eventId}`;
  if (!(await store.add(key, "processing", options.lockSeconds ?? 300))) {
    return (await store.get(key)) === "done" ? { status: "duplicate" } : { status: "in_progress" };
  }
  let result: T;
  try {
    result = await handler();
  } catch (error) {
    await store.delete(key);
    throw error;
  }
  await store.set(key, "done", options.ttlSeconds ?? 3 * 24 * 3600);
  return { status: "processed", result };
}

/**
 * Fetch-API handler for the adapter protocol. Mount it at your adapter base URL (it serves
 * `…/authenticate`, `…/user` and `…/event`) in Cloudflare Workers, Deno, Bun, Hono, or Node
 * with any Request/Response bridge (Express: `@whatwg-node/server`, Next.js route handlers…).
 */
export function adapterHandler(handlers: AdapterHandlers): (request: Request) => Promise<Response> {
  const signingSecret = Array.isArray(handlers.secret) ? handlers.secret[0]! : handlers.secret;
  return async (request) => {
    const url = new URL(request.url);
    const body = await request.text();
    const requestId = request.headers.get("9in-request-id") ?? "";
    const respond = async (status: number, payload: unknown) => {
      const text = payload === null ? "" : JSON.stringify(payload);
      const headers = new Headers({ [SIGNATURE_HEADER]: await signPayload(signingSecret, "POST", `${url.pathname}#${requestId}`, text) });
      if (text) headers.set("Content-Type", "application/json");
      return new Response(status === 204 ? null : text, { status, headers });
    };
    if (request.method !== "POST") return new Response("Method not allowed", { status: 405 });
    if (!(await verifySignature(handlers.secret, request.headers.get(SIGNATURE_HEADER), "POST", url.pathname, body, handlers.toleranceSeconds))) {
      return new Response(JSON.stringify({ error: "invalid_signature" }), { status: 401, headers: { "Content-Type": "application/json" } });
    }
    let input: Record<string, unknown>;
    try {
      input = JSON.parse(body || "{}") as Record<string, unknown>;
    } catch {
      return respond(400, { error: "invalid_json" });
    }
    const route = url.pathname.split("/").pop();
    if (route === "authenticate") {
      const result = await handlers.authenticate(input.identifier as AdapterIdentifier, String(input.password ?? ""));
      if (result === "invalid") return respond(401, { error: "invalid_credentials" });
      if (result === "blocked") return respond(403, { error: "blocked" });
      return respond(200, { user: result });
    }
    if (route === "user") {
      const user = await handlers.findUser(input.id ? { id: String(input.id) } : { identifier: input.identifier as AdapterIdentifier });
      return user ? respond(200, { user }) : respond(404, { error: "not_found" });
    }
    if (route === "event") {
      await handlers.onEvent?.(input as unknown as AdapterEvent);
      return respond(204, null);
    }
    return respond(404, { error: "not_found" });
  };
}
