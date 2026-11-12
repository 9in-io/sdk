import { afterEach, describe, expect, it, vi } from "vitest";
import { signature } from "./signature";
import { NineAuth, NineError } from "../src/index";
import { ManagementClient, MemoryEventStore, adapterHandler, createTokenVerifier, processEventOnce, verifyAccessToken, verifyWebhook } from "../src/server";
import { base64UrlEncode, normalizeIssuer, sha256 } from "../src/util";

const ISSUER = "https://acme.9in.test";

class Memory {
  map = new Map<string, string>();
  getItem(k: string) {
    return this.map.get(k) ?? null;
  }
  setItem(k: string, v: string) {
    this.map.set(k, v);
  }
  removeItem(k: string) {
    this.map.delete(k);
  }
}

const b64json = (o: unknown) => base64UrlEncode(new TextEncoder().encode(JSON.stringify(o)));
const unsignedJwt = (payload: Record<string, unknown>) => `${b64json({ alg: "RS256" })}.${b64json(payload)}.sig`;

function router(routes: Record<string, (req: Request) => Response | Promise<Response>>) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input as RequestInfo, init);
    const url = new URL(req.url);
    const handler = routes[`${req.method} ${url.origin}${url.pathname}`];
    if (!handler) return new Response("not found", { status: 404 });
    return handler(req);
  }) as unknown as typeof fetch & ReturnType<typeof vi.fn>;
}

const discovery = (issuer: string) => () =>
  Response.json({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    userinfo_endpoint: `${issuer}/oauth/userinfo`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    end_session_endpoint: `${issuer}/oauth/logout`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
  });

afterEach(() => vi.restoreAllMocks());

describe("NineAuth (browser)", () => {
  it("signs in with PKCE, refreshes once for concurrent callers and logs out", async () => {
    const issuer = `${ISSUER}/a${Math.random().toString(36).slice(2)}`;
    let tokenCalls = 0;
    let verifierSeen = "";
    const fetcher = router({
      [`GET ${issuer}/.well-known/openid-configuration`]: discovery(issuer),
      [`POST ${issuer}/oauth/token`]: async (req) => {
        tokenCalls++;
        const form = new URLSearchParams(await req.text());
        if (form.get("grant_type") === "authorization_code") {
          verifierSeen = form.get("code_verifier")!;
          return Response.json({ access_token: "at-1", refresh_token: "rt-1", expires_in: 1, id_token: unsignedJwt({ sub: "usr_1", aud: "app_1", nonce: pendingNonce, email: "jane@acme.test" }) });
        }
        expect(form.get("refresh_token")).toBe("rt-1");
        return Response.json({ access_token: "at-2", refresh_token: "rt-2", expires_in: 3600 });
      },
      [`POST ${issuer}/oauth/revoke`]: () => new Response(null, { status: 200 }),
    });
    let navigated = "";
    let pendingNonce = "";
    const auth = new NineAuth({ issuer, clientId: "app_1", redirectUri: "https://app.test/callback", storage: new Memory(), transientStorage: new Memory(), fetch: fetcher, navigate: (u) => (navigated = u) });
    await auth.login({ returnTo: "/dashboard", loginHint: "jane@acme.test" });
    const authorize = new URL(navigated);
    expect(authorize.pathname).toBe(`${new URL(issuer).pathname}/oauth/authorize`);
    expect(authorize.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorize.searchParams.get("login_hint")).toBe("jane@acme.test");
    pendingNonce = authorize.searchParams.get("nonce")!;

    await expect(auth.handleRedirect(`https://app.test/callback?code=c1&state=wrong`)).rejects.toThrow(/invalid_state/);
    await auth.login({ returnTo: "/dashboard" });
    const second = new URL(navigated);
    pendingNonce = second.searchParams.get("nonce")!;
    const result = await auth.handleRedirect(`https://app.test/callback?code=c1&state=${second.searchParams.get("state")}`);
    expect(result).toMatchObject({ returnTo: "/dashboard", user: { sub: "usr_1", email: "jane@acme.test" } });
    expect(base64UrlEncode(await sha256(verifierSeen))).toBe(second.searchParams.get("code_challenge"));

    // Token expires within a minute: two concurrent callers share one refresh.
    const [a, b] = await Promise.all([auth.getAccessToken(), auth.getAccessToken()]);
    expect([a, b]).toEqual(["at-2", "at-2"]);
    expect(tokenCalls).toBe(2);

    await auth.logout({ returnTo: "https://app.test" });
    const logout = new URL(navigated);
    expect(logout.pathname.endsWith("/oauth/logout")).toBe(true);
    expect(logout.searchParams.get("post_logout_redirect_uri")).toBe("https://app.test");
    expect(auth.isAuthenticated()).toBe(false);
    await expect(auth.getAccessToken()).rejects.toBeInstanceOf(NineError);
  });

  it("opens sign-up with prompt=create", async () => {
    const issuer = `${ISSUER}/b${Math.random().toString(36).slice(2)}`;
    let navigated = "";
    const auth = new NineAuth({ issuer, clientId: "app_1", redirectUri: "https://app.test/cb", storage: new Memory(), transientStorage: new Memory(), fetch: router({ [`GET ${issuer}/.well-known/openid-configuration`]: discovery(issuer) }), navigate: (u) => (navigated = u) });
    await auth.signup();
    expect(new URL(navigated).searchParams.get("prompt")).toBe("create");
  });
});

describe("verifyAccessToken (server)", () => {
  async function setup() {
    const issuer = `${ISSUER}/v${Math.random().toString(36).slice(2)}`;
    const pair = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const jwk = { ...(await crypto.subtle.exportKey("jwk", pair.publicKey)), kid: "k1", alg: "RS256", use: "sig" };
    const sign = async (payload: Record<string, unknown>, kid = "k1") => {
      const input = `${b64json({ alg: "RS256", typ: "at+jwt", kid })}.${b64json(payload)}`;
      const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, new TextEncoder().encode(input)));
      return `${input}.${base64UrlEncode(sig)}`;
    };
    const fetcher = router({
      [`GET ${issuer}/.well-known/openid-configuration`]: discovery(issuer),
      [`GET ${issuer}/.well-known/jwks.json`]: () => Response.json({ keys: [jwk] }),
    });
    const now = Math.floor(Date.now() / 1000);
    return { issuer, sign, fetcher, base: { iss: issuer, sub: "usr_1", aud: "https://api.acme.test", client_id: "app_1", scope: "orders:read orders:write", iat: now, exp: now + 300 } };
  }

  it("accepts valid tokens and rejects bad audience, expiry, scope and signature", async () => {
    const { issuer, sign, fetcher, base } = await setup();
    const opts = { issuer, audience: "https://api.acme.test", fetch: fetcher };
    await expect(verifyAccessToken(await sign(base), { ...opts, scope: "orders:read" })).resolves.toMatchObject({ sub: "usr_1" });
    await expect(verifyAccessToken(await sign({ ...base, aud: "https://other" }), opts)).rejects.toThrow(/audience/);
    await expect(verifyAccessToken(await sign({ ...base, exp: base.iat - 120 }), opts)).rejects.toThrow(/expired/);
    await expect(verifyAccessToken(await sign(base), { ...opts, scope: "admin" })).rejects.toMatchObject({ code: "insufficient_scope", status: 403 });
    const token = await sign(base);
    await expect(verifyAccessToken(token.slice(0, -4) + "AAAA", opts)).rejects.toThrow(/signature/);
    await expect(verifyAccessToken(await sign(base, "unknown"), opts)).rejects.toThrow(/unknown signing key/);
  });
});

describe("verifyAccessToken algorithms", () => {
  const PARAMS: Record<string, { gen: RsaHashedKeyGenParams | EcKeyGenParams | Algorithm; sign: AlgorithmIdentifier | RsaPssParams | EcdsaParams }> = {
    RS512: { gen: { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-512" } as RsaHashedKeyGenParams, sign: "RSASSA-PKCS1-v1_5" },
    PS256: { gen: { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" } as RsaHashedKeyGenParams, sign: { name: "RSA-PSS", saltLength: 32 } },
    ES256: { gen: { name: "ECDSA", namedCurve: "P-256" }, sign: { name: "ECDSA", hash: "SHA-256" } },
    ES384: { gen: { name: "ECDSA", namedCurve: "P-384" }, sign: { name: "ECDSA", hash: "SHA-384" } },
    EdDSA: { gen: { name: "Ed25519" }, sign: "Ed25519" },
  };

  async function signer(alg: string, jwkAlg = alg) {
    const issuer = `${ISSUER}/a${Math.random().toString(36).slice(2)}`;
    const pair = (await crypto.subtle.generateKey(PARAMS[alg]!.gen, true, ["sign", "verify"])) as CryptoKeyPair;
    const jwk = { ...(await crypto.subtle.exportKey("jwk", pair.publicKey)), kid: "k1", alg: jwkAlg, use: "sig" };
    const fetcher = router({
      [`GET ${issuer}/.well-known/openid-configuration`]: discovery(issuer),
      [`GET ${issuer}/.well-known/jwks.json`]: () => Response.json({ keys: [jwk] }),
    });
    const now = Math.floor(Date.now() / 1000);
    const claims = { iss: issuer, sub: "usr_1", aud: "https://api.acme.test", client_id: "app_1", scope: "orders:read", iat: now, exp: now + 300 };
    const sign = async (header: Record<string, unknown> = {}) => {
      const input = `${b64json({ alg, typ: "at+jwt", kid: "k1", ...header })}.${b64json(claims)}`;
      const sig = new Uint8Array(await crypto.subtle.sign(PARAMS[alg]!.sign, pair.privateKey, new TextEncoder().encode(input)));
      return `${input}.${base64UrlEncode(sig)}`;
    };
    return { issuer, fetcher, sign };
  }

  it.each(Object.keys(PARAMS))("verifies %s tokens from JWKS", async (alg) => {
    const { issuer, fetcher, sign } = await signer(alg);
    await expect(verifyAccessToken(await sign(), { issuer, audience: "https://api.acme.test", fetch: fetcher })).resolves.toMatchObject({ sub: "usr_1" });
  });

  it("rejects a token whose alg differs from its key, and ID tokens", async () => {
    const { issuer, fetcher, sign } = await signer("PS256", "RS256");
    await expect(verifyAccessToken(await sign(), { issuer, fetch: fetcher })).rejects.toThrow(/does not match the key/);
    const es = await signer("ES256");
    await expect(verifyAccessToken(await es.sign({ typ: "JWT" }), { issuer: es.issuer, fetch: es.fetcher })).rejects.toThrow(/not an access token/);
  });

  it("verifies HMAC tokens with the API's shared secret only", async () => {
    const issuer = `${ISSUER}/h${Math.random().toString(36).slice(2)}`;
    const secret = "an-api-secret-of-at-least-32-bytes-long";
    const now = Math.floor(Date.now() / 1000);
    const input = `${b64json({ alg: "HS256", typ: "at+jwt", kid: "hk" })}.${b64json({ iss: issuer, sub: "app_1", aud: "https://api.acme.test", client_id: "app_1", scope: "orders:read", iat: now, exp: now + 60 })}`;
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const token = `${input}.${base64UrlEncode(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(input))))}`;
    await expect(verifyAccessToken(token, { issuer, secret })).resolves.toMatchObject({ sub: "app_1" });
    await expect(verifyAccessToken(token, { issuer, secret: `${secret}x` })).rejects.toThrow(/signature/);
    await expect(verifyAccessToken(token, { issuer })).rejects.toThrow(/secret/);
  });
});

describe("createTokenVerifier (hybrid)", () => {
  async function setup(answers: (token: string) => Record<string, unknown>) {
    const issuer = `${ISSUER}/y${Math.random().toString(36).slice(2)}`;
    const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const jwk = { ...(await crypto.subtle.exportKey("jwk", pair.publicKey)), kid: "k1", alg: "ES256", use: "sig" };
    const introspections: string[] = [];
    const fetcher = router({
      [`GET ${issuer}/.well-known/openid-configuration`]: () => Response.json({ issuer, token_endpoint: `${issuer}/oauth/token`, jwks_uri: `${issuer}/.well-known/jwks.json`, introspection_endpoint: `${issuer}/oauth/introspect` }),
      [`GET ${issuer}/.well-known/jwks.json`]: () => Response.json({ keys: [jwk] }),
      [`POST ${issuer}/oauth/introspect`]: async (req) => {
        expect(req.headers.get("authorization")).toBe(`Basic ${btoa("api:secret")}`);
        const token = new URLSearchParams(await req.text()).get("token")!;
        introspections.push(token);
        return Response.json(answers(token));
      },
    });
    const now = Math.floor(Date.now() / 1000);
    const claims = (extra: Record<string, unknown> = {}) => ({ iss: issuer, sub: "usr_1", aud: "https://api.acme.test", client_id: "app_1", scope: "orders:read", sid: "sid_1", iat: now, exp: now + 300, jti: "j1", ...extra });
    const sign = async (payload: Record<string, unknown>) => {
      const input = `${b64json({ alg: "ES256", typ: "at+jwt", kid: "k1" })}.${b64json(payload)}`;
      const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, new TextEncoder().encode(input)));
      return `${input}.${base64UrlEncode(sig)}`;
    };
    const options = { issuer, audience: "https://api.acme.test", clientId: "api", clientSecret: "secret", fetch: fetcher };
    return { issuer, sign, claims, introspections, options };
  }

  it("introspects once, serves from cache, and drops the answer on token.revoked", async () => {
    const revoked = new Set<string>();
    const { sign, claims, introspections, options } = await setup((token) => (revoked.has(token) ? { active: false } : { active: true, ...claims() }));
    const verifier = createTokenVerifier(options);
    const token = await sign(claims());
    await expect(verifier.verify(token, { scope: "orders:read" })).resolves.toMatchObject({ sub: "usr_1" });
    await verifier.verify(token);
    expect(introspections).toHaveLength(1);
    await expect(verifier.verify(token, { scope: "admin" })).rejects.toMatchObject({ code: "insufficient_scope" });

    revoked.add(token);
    expect(verifier.handleEvent({ event_type: "token.revoked", data: { token_type: "refresh_token", sid: "sid_1" } })).toBe(0);
    expect(verifier.handleEvent({ event_type: "token.revoked", data: { token_type: "access_token", jti: "j1" } })).toBe(1);
    await expect(verifier.verify(token)).rejects.toThrow(/revoked/);
    await expect(verifier.verify(token)).rejects.toThrow(/revoked/);
    expect(introspections).toHaveLength(2); // the refusal is remembered
  });

  it("evicts by session and by user", async () => {
    const { sign, claims, introspections, options } = await setup(() => ({ active: true }));
    const verifier = createTokenVerifier(options);
    const a = await sign(claims({ jti: "a" }));
    const b = await sign(claims({ jti: "b", sid: "sid_2" }));
    await verifier.verify(a);
    await verifier.verify(b);
    expect(verifier.handleEvent({ event_type: "session.revoked", data: { sid: "sid_2", user: { id: "usr_1" } } })).toBe(1);
    expect(verifier.handleEvent({ event_type: "user.sessions_revoked", data: { count: 1, user: { id: "usr_1" } } })).toBe(1);
    expect(verifier.handleEvent({ event_type: "user.login", data: { user: { id: "usr_1" } } })).toBe(0);
    // The old shape no longer evicts anything.
    expect(verifier.handleEvent({ event_type: "user.deleted", data: { userId: "usr_1" } })).toBe(0);
    await verifier.verify(a);
    expect(introspections).toHaveLength(3);
  });

  it("introspects opaque tokens and checks their audience", async () => {
    const { claims, introspections, options } = await setup((token) => (token === "9in_at_good" ? { active: true, token_type: "access_token", ...claims() } : { active: true, ...claims({ aud: "https://other" }) }));
    const verifier = createTokenVerifier(options);
    await expect(verifier.verify("9in_at_good")).resolves.toMatchObject({ sub: "usr_1", sid: "sid_1" });
    await expect(verifier.verify("9in_at_other")).rejects.toThrow(/audience/);
    expect(introspections).toEqual(["9in_at_good", "9in_at_other"]);
    await expect(createTokenVerifier({ ...options, mode: "local" }).verify("9in_at_good")).rejects.toThrow(/opaque/);
  });

  it("supports local and introspect modes", async () => {
    const { sign, claims, introspections, options } = await setup(() => ({ active: true, ...claims() }));
    const token = await sign(claims());
    const local = createTokenVerifier({ issuer: options.issuer, fetch: options.fetch, mode: "local" });
    await local.verify(token);
    expect(introspections).toHaveLength(0);
    const strict = createTokenVerifier({ ...options, mode: "introspect" });
    await strict.verify(token);
    await strict.verify(token);
    expect(introspections).toHaveLength(2);
    expect(() => createTokenVerifier({ issuer: options.issuer })).toThrow(/clientId and clientSecret/);
  });
});

describe("adapterHandler (server)", () => {
  it("interoperates with 9in's signature implementation in both directions", async () => {
    const secret = "adapter-secret";
    const handler = adapterHandler({
      secret,
      authenticate: async (identifier, password) => (identifier.value === "jane@acme.test" && password === "pw" ? { id: "42", email: "jane@acme.test", email_verified: true } : "invalid"),
      findUser: async (q) => ("id" in q && q.id === "42" ? { id: "42", email: "jane@acme.test" } : null),
    });
    const call = async (path: string, body: unknown, header?: string) => {
      const raw = JSON.stringify(body);
      const res = await handler(
        new Request(`https://customer.test/9in${path}`, {
          method: "POST",
          body: raw,
          headers: { "9in-signature": header ?? (await signature.sign({ secret, method: "POST", path: `/9in${path}`, body: raw })), "9in-request-id": "req-1" },
        }),
      );
      const text = await res.text();
      const verified = await signature.verify({ secret, header: res.headers.get("9in-signature"), method: "POST", path: `/9in${path}#req-1`, body: text });
      return { status: res.status, json: text ? JSON.parse(text) : null, verified: verified.ok };
    };
    expect(await call("/authenticate", { identifier: { type: "email", value: "jane@acme.test" }, password: "pw" })).toMatchObject({ status: 200, verified: true, json: { user: { id: "42" } } });
    expect(await call("/authenticate", { identifier: { type: "email", value: "jane@acme.test" }, password: "nope" })).toMatchObject({ status: 401, verified: true });
    expect(await call("/user", { id: "42" })).toMatchObject({ status: 200, verified: true });
    expect(await call("/user", { id: "nope" })).toMatchObject({ status: 404, verified: true });
    expect(await call("/event", { id: "e1", event_type: "user.updated", created_at: new Date().toISOString(), data: { user_id: "42", fields: ["name"] } })).toMatchObject({ status: 204, verified: true });
    expect((await call("/user", { id: "42" }, "t=1,v1=" + "0".repeat(64))).status).toBe(401);
  });
});

describe("ManagementClient (server)", () => {
  it("authenticates with client credentials, one token per scope, cached", async () => {
    const issuer = `${ISSUER}/m${Math.random().toString(36).slice(2)}`;
    const scopes: string[] = [];
    const fetcher = router({
      [`GET ${issuer}/.well-known/openid-configuration`]: discovery(issuer),
      [`POST ${issuer}/oauth/token`]: async (req) => {
        expect(req.headers.get("authorization")).toBe(`Basic ${btoa("svc:secret")}`);
        scopes.push(new URLSearchParams(await req.text()).get("scope") ?? "");
        return Response.json({ access_token: "mgmt", expires_in: 3600 });
      },
      [`GET ${issuer}/api/v1/users`]: (req) => {
        expect(req.headers.get("authorization")).toBe("Bearer mgmt");
        return Response.json({ users: [{ id: "usr_1" }], next_cursor: null, total: 1 });
      },
      [`DELETE ${issuer}/api/v1/users/usr_1`]: () => new Response(null, { status: 204 }),
    });
    const client = new ManagementClient({ issuer, clientId: "svc", clientSecret: "secret", fetch: fetcher });
    expect((await client.listUsers({ query: "jane" })).users).toHaveLength(1);
    await client.deleteUser("usr_1");
    await client.listUsers();
    // An app granted only some management scopes still works: each call asks for its own.
    expect(scopes).toEqual(["management:users:read", "management:users:write"]);
  });
});

describe("verifyWebhook", () => {
  const secret = "whsec_sdk_test";
  const event = { id: "evt_1", event_type: "user.created", created_at: "2026-11-09T08:00:00.000Z", tenant: "tnt_abc", environment: "production", data: { user: { id: "usr_1" } } };
  const body = JSON.stringify(event);
  const url = "https://api.customer.test/hooks/9in?source=webhook";
  const post = (header: string | null, payload = body, method = "POST") =>
    new Request(url, { method, headers: header ? { "9in-signature": header } : {}, body: method === "POST" ? payload : undefined });

  it("accepts a request signed by 9in (core signer, path without the query) and returns the event", async () => {
    const header = await signature.sign({ secret, method: "POST", path: "/hooks/9in", body });
    expect(await verifyWebhook(secret, post(header))).toEqual(event);
    // Rotation: any of several secrets.
    expect((await verifyWebhook(["old-secret", secret], post(header))).id).toBe("evt_1");
  });

  it("rejects missing, wrong, tampered, stale and non-POST requests", async () => {
    const header = await signature.sign({ secret, method: "POST", path: "/hooks/9in", body });
    const rejects = async (request: Request, s: string | string[] = secret) => {
      const error = await verifyWebhook(s, request).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(NineError);
      expect(error).toMatchObject({ code: "invalid_signature", status: 401 });
    };
    await rejects(post(null));
    await rejects(post(header), "another-secret");
    await rejects(post(header, body.replace("usr_1", "usr_2")));
    await rejects(post(await signature.sign({ secret, method: "POST", path: "/other", body })));
    await rejects(post(await signature.sign({ secret, method: "POST", path: "/hooks/9in", body, timestamp: Math.floor(Date.now() / 1000) - 3600 })));
    await rejects(post(header, body, "GET"));
  });

  it("supports a path override and a custom tolerance", async () => {
    const old = await signature.sign({ secret, method: "POST", path: "/public/hooks", body, timestamp: Math.floor(Date.now() / 1000) - 600 });
    expect((await verifyWebhook(secret, post(old), { path: "/public/hooks", toleranceSeconds: 900 })).event_type).toBe("user.created");
  });
});

describe("issuer validation", () => {
  it("requires https except for localhost", () => {
    expect(normalizeIssuer("https://acme.9in.io/")).toBe("https://acme.9in.io");
    for (const local of ["http://localhost:8787", "http://acme.localhost:8787", "http://127.0.0.1:8897", "http://[::1]:8897"]) {
      expect(normalizeIssuer(local)).toBe(local);
    }
    for (const insecure of ["http://acme.9in.io", "http://login.acme.com", "http://localhost.evil.com"]) {
      expect(() => normalizeIssuer(insecure)).toThrow(NineError);
    }
    expect(normalizeIssuer("http://auth:8897", true)).toBe("http://auth:8897");
    for (const invalid of ["acme.9in.io", "https://acme.9in.io/?x=1", "https://acme.9in.io/#f", "https://user:pw@acme.9in.io", "ftp://acme.9in.io"]) {
      expect(() => normalizeIssuer(invalid)).toThrow(NineError);
    }
  });

  it("is enforced by NineAuth, verifyAccessToken and ManagementClient", async () => {
    expect(() => new NineAuth({ issuer: "http://acme.9in.io", clientId: "a", redirectUri: "https://app/cb" })).toThrow(/https/);
    expect(() => new ManagementClient({ issuer: "http://acme.9in.io", clientId: "a", clientSecret: "s" })).toThrow(/https/);
    await expect(verifyAccessToken("x.y.z", { issuer: "http://acme.9in.io" })).rejects.toMatchObject({ code: "insecure_issuer" });
    expect(() => new NineAuth({ issuer: "http://auth.internal:8897", clientId: "a", redirectUri: "http://app/cb", allowInsecureIssuer: true })).not.toThrow();
  });
});

describe("processEventOnce", () => {
  it("runs a handler once per event id", async () => {
    const store = new MemoryEventStore();
    const handler = vi.fn(async () => "ok");
    expect(await processEventOnce(store, "evt_1", handler)).toEqual({ status: "processed", result: "ok" });
    expect(await processEventOnce(store, "evt_1", handler)).toEqual({ status: "duplicate" });
    expect(await processEventOnce(store, "evt_2", handler)).toEqual({ status: "processed", result: "ok" });
    expect(handler).toHaveBeenCalledTimes(2);
  });

  it("reports a delivery that is still running as in_progress", async () => {
    const store = new MemoryEventStore();
    let release!: () => void;
    const first = processEventOnce(store, "evt_slow", () => new Promise<void>((resolve) => (release = resolve)));
    expect(await processEventOnce(store, "evt_slow", () => undefined)).toEqual({ status: "in_progress" });
    release();
    expect((await first).status).toBe("processed");
    expect(await processEventOnce(store, "evt_slow", () => undefined)).toEqual({ status: "duplicate" });
  });

  it("releases the id when the handler fails so a retry can process it", async () => {
    const store = new MemoryEventStore();
    await expect(processEventOnce(store, "evt_fail", () => Promise.reject(new Error("db down")))).rejects.toThrow("db down");
    expect(await processEventOnce(store, "evt_fail", () => 1)).toEqual({ status: "processed", result: 1 });
  });

  it("forgets ids after the ttl", async () => {
    vi.useFakeTimers();
    try {
      const store = new MemoryEventStore();
      await processEventOnce(store, "evt_old", () => 1, { ttlSeconds: 60 });
      vi.advanceTimersByTime(61_000);
      expect((await processEventOnce(store, "evt_old", () => 2)).status).toBe("processed");
    } finally {
      vi.useRealTimers();
    }
  });
});
