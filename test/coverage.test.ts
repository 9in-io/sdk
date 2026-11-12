import { afterEach, describe, expect, it, vi } from "vitest";
import { signature } from "./signature";
import { NineAuth, NineError } from "../src/index";
import { ManagementClient, adapterHandler, verifyAccessToken } from "../src/server";
import { base64UrlEncode } from "../src/util";

const ISSUER = "https://acme.9in.test";
const unique = (p: string) => `${ISSUER}/${p}${Math.random().toString(36).slice(2)}`;

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

type Handler = (req: Request) => Response | Promise<Response>;
function router(routes: Record<string, Handler>) {
  const calls: Request[] = [];
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input as RequestInfo, init);
    calls.push(req.clone());
    const url = new URL(req.url);
    const handler = routes[`${req.method} ${url.origin}${url.pathname}`];
    return handler ? handler(req) : new Response("not found", { status: 404 });
  }) as unknown as typeof fetch;
  return { fetcher, calls };
}

const discovery = (issuer: string, extra: Record<string, unknown> = {}) => () =>
  Response.json({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    userinfo_endpoint: `${issuer}/oauth/userinfo`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    end_session_endpoint: `${issuer}/oauth/logout`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    ...extra,
  });

afterEach(() => vi.restoreAllMocks());

// ---------------------------------------------------------------------------
// NineAuth

/** A NineAuth with a fake tenant. `token` answers the token endpoint. */
function browserClient(token: Handler, more: Record<string, Handler> = {}, discoveryExtra: Record<string, unknown> = {}) {
  const issuer = unique("b");
  const { fetcher, calls } = router({
    [`GET ${issuer}/.well-known/openid-configuration`]: discovery(issuer, discoveryExtra),
    [`POST ${issuer}/oauth/token`]: token,
    ...Object.fromEntries(Object.entries(more).map(([k, v]) => [k.replace("{issuer}", issuer), v])),
  });
  const navigated: string[] = [];
  const storage = new Memory();
  const auth = new NineAuth({ issuer, clientId: "app_1", redirectUri: "https://app.test/cb", storage, transientStorage: new Memory(), fetch: fetcher, navigate: (u) => void navigated.push(u) });
  /** Starts a login and returns the matching callback URL (and the nonce 9in must echo). */
  const start = async (params: Record<string, string> = {}) => {
    await auth.login({ returnTo: "/back" });
    const authorize = new URL(navigated.pop()!);
    const callback = new URL("https://app.test/cb");
    callback.searchParams.set("code", "c1");
    callback.searchParams.set("state", authorize.searchParams.get("state")!);
    for (const [k, v] of Object.entries(params)) callback.searchParams.set(k, v);
    return { callback: callback.toString(), nonce: authorize.searchParams.get("nonce")! };
  };
  return { issuer, auth, storage, calls, navigated, start };
}

describe("NineAuth edge cases", () => {
  it("requires issuer, clientId and redirectUri", () => {
    expect(() => new NineAuth({ issuer: ISSUER, clientId: "", redirectUri: "https://app.test/cb" })).toThrow(NineError);
  });

  it("keeps no tokens when the ID token fails its checks", async () => {
    let nonce = "";
    const wrongAudience = browserClient(() => Response.json({ access_token: "at", refresh_token: "rt", id_token: unsignedJwt({ sub: "usr_1", aud: "app_other", nonce }) }));
    let started = await wrongAudience.start();
    nonce = started.nonce;
    await expect(wrongAudience.auth.handleRedirect(started.callback)).rejects.toMatchObject({ code: "invalid_id_token" });
    expect(wrongAudience.auth.getTokens()).toBeNull();
    expect(wrongAudience.auth.isAuthenticated()).toBe(false);

    const wrongNonce = browserClient(() => Response.json({ access_token: "at", refresh_token: "rt", id_token: unsignedJwt({ sub: "usr_1", aud: ["app_1"], nonce: "replayed" }) }));
    started = await wrongNonce.start();
    await expect(wrongNonce.auth.handleRedirect(started.callback)).rejects.toMatchObject({ code: "invalid_id_token" });
    expect(wrongNonce.auth.isAuthenticated()).toBe(false);
  });

  it("reports 9in errors, missing codes, missing logins and foreign issuers", async () => {
    const { auth, start, calls, issuer } = browserClient(() => Response.json({ access_token: "at" }));
    let started = await start({ error: "access_denied", error_description: "The user said no" });
    const denied = new URL(started.callback);
    denied.searchParams.delete("code");
    await expect(auth.handleRedirect(denied.toString())).rejects.toMatchObject({ code: "access_denied", message: "access_denied: The user said no" });

    started = await start();
    const noCode = new URL(started.callback);
    noCode.searchParams.delete("code");
    await expect(auth.handleRedirect(noCode.toString())).rejects.toMatchObject({ code: "missing_code" });

    // The pending login is single-use: the same callback again has nothing to match.
    started = await start({ iss: "https://evil.test" });
    await expect(auth.handleRedirect(started.callback)).rejects.toMatchObject({ code: "invalid_issuer" });
    await expect(auth.handleRedirect(started.callback)).rejects.toMatchObject({ code: "invalid_state" });
    expect(calls.filter((r) => r.url.endsWith("/oauth/token"))).toHaveLength(0);

    // The issuer in discovery (a trailing slash differs) is accepted.
    started = await start({ iss: `${issuer}/` });
    await expect(auth.handleRedirect(started.callback)).resolves.toMatchObject({ returnTo: "/back" });
  });

  it("reads the user, asks userinfo with the token, and maps userinfo errors", async () => {
    let userinfo = 200;
    const { auth, start, calls } = browserClient(
      () => Response.json({ access_token: "at-1", refresh_token: "rt-1", expires_in: 3600, id_token: unsignedJwt({ sub: "usr_1", aud: "app_1", nonce: currentNonce, email: "jane@acme.test" }) }),
      { "GET {issuer}/oauth/userinfo": () => (userinfo === 200 ? Response.json({ sub: "usr_1", email: "fresh@acme.test" }) : new Response("no", { status: userinfo })) },
    );
    expect(await auth.getUser()).toBeNull();
    await expect(auth.getAccessToken()).rejects.toMatchObject({ code: "login_required" });
    let currentNonce = "";
    const started = await start();
    currentNonce = started.nonce;
    await auth.handleRedirect(started.callback);
    expect((await auth.getUser())?.email).toBe("jane@acme.test");
    expect((await auth.fetchUserInfo()).email).toBe("fresh@acme.test");
    expect(calls.find((r) => r.url.endsWith("/oauth/userinfo"))!.headers.get("authorization")).toBe("Bearer at-1");
    userinfo = 401;
    await expect(auth.fetchUserInfo()).rejects.toMatchObject({ code: "userinfo_failed", status: 401 });
  });

  it("signs out locally when the refresh token is refused, and keeps tokens on other errors", async () => {
    let answer: () => Response = () => Response.json({ error: "server_error" }, { status: 500 });
    let nonce = "";
    let first = true;
    const { auth, start, storage } = browserClient(() => {
      if (first) {
        first = false;
        return Response.json({ access_token: "at-1", refresh_token: "rt-1", expires_in: 1, id_token: unsignedJwt({ sub: "usr_1", aud: "app_1", nonce }) });
      }
      return answer();
    });
    const started = await start();
    nonce = started.nonce;
    await auth.handleRedirect(started.callback);
    await expect(auth.getAccessToken()).rejects.toMatchObject({ code: "server_error" });
    expect(auth.getTokens()?.refreshToken).toBe("rt-1"); // a hiccup does not sign the user out
    answer = () => Response.json({ error: "invalid_grant" }, { status: 400 });
    await expect(auth.getAccessToken()).rejects.toMatchObject({ code: "login_required" });
    expect([...storage.map.keys()].some((k) => k.endsWith(":tokens"))).toBe(false);
  });

  it("attaches the token in fetch() and keeps the caller's headers", async () => {
    let nonce = "";
    const { auth, start, calls } = browserClient(() => Response.json({ access_token: "at-9", expires_in: 3600, id_token: unsignedJwt({ sub: "usr_1", aud: "app_1", nonce }) }), {
      "POST {issuer}/api/things": () => new Response("ok"),
    });
    const started = await start();
    nonce = started.nonce;
    await auth.handleRedirect(started.callback);
    const api = calls[0]!.url.replace(/\/\.well-known.*$/, "/api/things");
    await auth.fetch(api, { method: "POST", headers: { "x-trace": "t1" }, body: "{}" });
    const sent = calls.find((r) => r.url === api)!;
    expect(sent.headers.get("authorization")).toBe("Bearer at-9");
    expect(sent.headers.get("x-trace")).toBe("t1");
  });

  it("logs out: revokes, then navigates unless local; a failed revocation does not block it", async () => {
    let nonce = "";
    let revokeStatus = 200;
    const { auth, start, calls, navigated } = browserClient(() => Response.json({ access_token: "at", refresh_token: "rt-x", id_token: unsignedJwt({ sub: "usr_1", aud: "app_1", nonce }) }), {
      "POST {issuer}/oauth/revoke": () => new Response(null, { status: revokeStatus }),
    });
    let started = await start();
    nonce = started.nonce;
    await auth.handleRedirect(started.callback);
    await auth.logout({ local: true });
    const revoke = new URLSearchParams(await calls.find((r) => r.url.endsWith("/oauth/revoke"))!.text());
    expect(Object.fromEntries(revoke)).toEqual({ token: "rt-x", token_type_hint: "refresh_token", client_id: "app_1" });
    expect(navigated).toEqual([]);
    expect(auth.isAuthenticated()).toBe(false);

    started = await start();
    nonce = started.nonce;
    await auth.handleRedirect(started.callback);
    revokeStatus = 503;
    await auth.logout();
    const url = new URL(navigated.pop()!);
    expect(url.searchParams.get("client_id")).toBe("app_1");
    expect(url.searchParams.get("id_token_hint")).toBeTruthy();
    expect(url.searchParams.has("post_logout_redirect_uri")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// ManagementClient

describe("ManagementClient requests and errors", () => {
  function management(routes: Record<string, Handler>, expiresIn = 3600) {
    const issuer = unique("m");
    const scopes: string[] = [];
    const { fetcher, calls } = router({
      [`GET ${issuer}/.well-known/openid-configuration`]: discovery(issuer),
      [`POST ${issuer}/oauth/token`]: async (req) => {
        scopes.push(new URLSearchParams(await req.text()).get("scope")!);
        return Response.json({ access_token: `tok-${scopes.length}`, expires_in: expiresIn });
      },
      ...Object.fromEntries(Object.entries(routes).map(([k, v]) => [k.replace("{issuer}", issuer), v])),
    });
    return { client: new ManagementClient({ issuer, clientId: "svc", clientSecret: "s3cr:t", fetch: fetcher }), calls, scopes, issuer };
  }
  const user = { id: "usr/1", email: "jane@acme.test" };

  it("maps every method to its endpoint, encoding ids and using API field names", async () => {
    const echo: Handler = async (req) => Response.json({ user, method: req.method, body: req.method === "GET" ? null : await req.text() });
    const { client, calls, scopes } = management({
      "GET {issuer}/api/v1/users/usr%2F1": echo,
      "GET {issuer}/api/v1/users/lookup": echo,
      "POST {issuer}/api/v1/users": echo,
      "PATCH {issuer}/api/v1/users/usr%2F1": echo,
      "POST {issuer}/api/v1/users/usr%2F1/login-link": () => Response.json({ url: "https://acme.9in.test/l/abc", expires_at: "2026-11-10T09:40:00.000Z" }),
      "DELETE {issuer}/api/v1/users/usr%2F1/sessions": () => Response.json({ revoked: 2 }),
    });
    await client.getUser("usr/1");
    await client.findUserByEmail("jane+x@acme.test");
    await client.createUser({ email: "jane@acme.test", email_verified: true });
    await client.updateUser("usr/1", { name: "Jane" });
    await client.blockUser("usr/1");
    await client.blockUser("usr/1", false);
    expect(await client.createLoginLink("usr/1", { returnTo: "https://app.test/cb", ttlSeconds: 60 })).toEqual({ url: "https://acme.9in.test/l/abc", expires_at: "2026-11-10T09:40:00.000Z" });
    await client.createLoginLink("usr/1");
    expect(await client.revokeUserSessions("usr/1")).toEqual({ revoked: 2 });

    const api = calls.filter((r) => r.url.includes("/api/v1/"));
    const bodies = await Promise.all(api.map(async (r) => [r.method, new URL(r.url).pathname.replace(/^\/[^/]+/, "") + new URL(r.url).search, await r.text()]));
    expect(bodies).toEqual([
      ["GET", "/api/v1/users/usr%2F1", ""],
      ["GET", "/api/v1/users/lookup?email=jane%2Bx%40acme.test", ""],
      ["POST", "/api/v1/users", JSON.stringify({ email: "jane@acme.test", email_verified: true })],
      ["PATCH", "/api/v1/users/usr%2F1", JSON.stringify({ name: "Jane" })],
      ["PATCH", "/api/v1/users/usr%2F1", JSON.stringify({ blocked: true })],
      ["PATCH", "/api/v1/users/usr%2F1", JSON.stringify({ blocked: false })],
      ["POST", "/api/v1/users/usr%2F1/login-link", JSON.stringify({ return_to: "https://app.test/cb", ttl_seconds: 60 })],
      ["POST", "/api/v1/users/usr%2F1/login-link", "{}"],
      ["DELETE", "/api/v1/users/usr%2F1/sessions", ""],
    ]);
    expect(api.filter((r) => r.method !== "GET").every((r) => r.headers.get("content-type") === "application/json" || r.method === "DELETE")).toBe(true);
    expect(scopes).toEqual(["management:users:read", "management:users:write", "management:sessions:write"]);
    // client_secret_basic with form-encoded credentials (RFC 6749 2.3.1).
    expect(calls.find((r) => r.url.endsWith("/oauth/token"))!.headers.get("authorization")).toBe(`Basic ${btoa("svc:s3cr%3At")}`);
  });

  it("lists and ends sessions, looks users up by any identifier, and imports in bulk", async () => {
    const at = "2026-11-10T09:30:00.000Z";
    const session = { sid: "s/1", user_id: "usr_1", auth_time: at, amr: ["pwd"], ip: "1.2.3.4", user_agent: "UA", created_at: at, last_seen_at: at, expires_at: at };
    const { client, calls, scopes } = management({
      "GET {issuer}/api/v1/users/usr_1/sessions": () => Response.json({ sessions: [session] }),
      "DELETE {issuer}/api/v1/sessions/s%2F1": () => new Response(null, { status: 204 }),
      "GET {issuer}/api/v1/users/lookup": () => Response.json({ user }),
      "POST {issuer}/api/v1/users/import": () => Response.json({ results: [{ index: 0, ok: true, status: "created", id: "legacy|42" }, { index: 1, ok: false, status: "failed", error: "unsupported_password_hash" }] }),
    });
    expect(await client.listUserSessions("usr_1")).toEqual({ sessions: [session] });
    expect(await client.revokeSession("s/1")).toBeUndefined();
    await client.findUser("phone_number", "+447700900000");
    await client.findUser("username", "jane");
    const { results } = await client.importUsers([{ id: "legacy|42", email: "a@acme.test", password_hash: "$2b$10$abcdefghijklmnopqrstuuF3S2bmKzXkP0e4m7S5Tg5G2v7G2.WmS", created_at: "2020-01-01T00:00:00Z" }, { email: "b@acme.test", password_hash: "md5:nope" }], { onConflict: "update", source: "auth0" });
    expect(results.map((r) => r.status)).toEqual(["created", "failed"]);

    const api = calls.filter((r) => r.url.includes("/api/v1/"));
    expect(api.map((r) => `${r.method} ${new URL(r.url).pathname.replace(/^\/[^/]+/, "")}${new URL(r.url).search}`)).toEqual([
      "GET /api/v1/users/usr_1/sessions",
      "DELETE /api/v1/sessions/s%2F1",
      "GET /api/v1/users/lookup?phone_number=%2B447700900000",
      "GET /api/v1/users/lookup?username=jane",
      "POST /api/v1/users/import",
    ]);
    const imported = JSON.parse(await api[4]!.text());
    expect(imported).toMatchObject({ on_conflict: "update", source: "auth0", users: [{ id: "legacy|42" }, { email: "b@acme.test" }] });
    // Listing sessions only reads; ending one needs the sessions scope.
    expect(scopes).toEqual(["management:users:read", "management:sessions:write", "management:users:write"]);
  });

  it("turns API errors into NineError with the API's code and status", async () => {
    const { client } = management({
      "GET {issuer}/api/v1/users/usr_404": () => Response.json({ error: "not_found", error_description: "no such user" }, { status: 404 }),
      "POST {issuer}/api/v1/users": () => Response.json({ error: "conflict" }, { status: 409 }),
      "DELETE {issuer}/api/v1/users/usr_502": () => new Response("<html>bad gateway</html>", { status: 502 }),
    });
    await expect(client.getUser("usr_404")).rejects.toMatchObject({ code: "not_found", message: "not_found: no such user", status: 404 });
    await expect(client.createUser({ email: "a@b.test" })).rejects.toMatchObject({ code: "conflict", message: "conflict: HTTP 409", status: 409 });
    await expect(client.deleteUser("usr_502")).rejects.toMatchObject({ code: "request_failed", status: 502 });
  });

  it("asks for a new token when the cached one is about to expire", async () => {
    const { client, scopes } = management({ "GET {issuer}/api/v1/users": () => Response.json({ users: [], next_cursor: null, total: 0 }) }, 20);
    await client.listUsers();
    await client.listUsers();
    expect(scopes).toEqual(["management:users:read", "management:users:read"]);
  });

  it("refuses an invalid client secret with invalid_client", async () => {
    const issuer = unique("m");
    const { fetcher } = router({
      [`GET ${issuer}/.well-known/openid-configuration`]: discovery(issuer),
      [`POST ${issuer}/oauth/token`]: () => Response.json({ error: "invalid_client" }, { status: 401 }),
    });
    await expect(new ManagementClient({ issuer, clientId: "svc", clientSecret: "wrong", fetch: fetcher }).listUsers()).rejects.toMatchObject({ code: "invalid_client", status: 401 });
  });
});

// ---------------------------------------------------------------------------
// adapterHandler

describe("adapterHandler branches", () => {
  const secret = "adapter-secret";
  const events: unknown[] = [];
  const handler = adapterHandler({
    secret: [secret, "old-secret"],
    authenticate: async (identifier) => (identifier.value === "blocked@acme.test" ? "blocked" : "invalid"),
    findUser: async (q) => ("identifier" in q && q.identifier.value === "jane@acme.test" ? { id: "42" } : null),
    onEvent: async (event) => void events.push(event),
  });
  async function call(path: string, raw: string, options: { secret?: string; method?: string; header?: string } = {}) {
    const header = options.header ?? (await signature.sign({ secret: options.secret ?? secret, method: "POST", path: `/9in${path}`, body: raw }));
    const res = await handler(new Request(`https://customer.test/9in${path}`, { method: options.method ?? "POST", body: options.method === "GET" ? undefined : raw, headers: { "9in-signature": header, "9in-request-id": "rq" } }));
    const text = await res.text();
    const signed = (await signature.verify({ secret, header: res.headers.get("9in-signature"), method: "POST", path: `/9in${path}#rq`, body: text })).ok;
    return { status: res.status, body: text && res.headers.get("content-type")?.includes("json") ? JSON.parse(text) : text || null, signed };
  }

  it("answers blocked, unknown and malformed requests, signed with the current secret", async () => {
    expect(await call("/authenticate", JSON.stringify({ identifier: { type: "email", value: "blocked@acme.test" }, password: "x" }))).toEqual({ status: 403, body: { error: "blocked" }, signed: true });
    expect(await call("/user", JSON.stringify({ identifier: { type: "email", value: "jane@acme.test" } }))).toEqual({ status: 200, body: { user: { id: "42" } }, signed: true });
    expect(await call("/user", JSON.stringify({ identifier: { type: "email", value: "nobody@acme.test" } }))).toEqual({ status: 404, body: { error: "not_found" }, signed: true });
    expect(await call("/authenticate", "{not json")).toEqual({ status: 400, body: { error: "invalid_json" }, signed: true });
    expect(await call("/unknown", "{}")).toEqual({ status: 404, body: { error: "not_found" }, signed: true });
  });

  it("accepts the previous secret during rotation and passes events on", async () => {
    const event = { id: "evt_1", event_type: "user.updated", created_at: "2026-11-09T00:00:00.000Z", data: { user_id: "42", fields: ["name"] } };
    expect(await call("/event", JSON.stringify(event), { secret: "old-secret" })).toEqual({ status: 204, body: null, signed: true });
    expect(events).toEqual([event]);
  });

  it("refuses unsigned, stale, and non-POST requests", async () => {
    expect((await call("/user", "{}", { secret: "wrong" })).status).toBe(401);
    const stale = `t=${Math.floor(Date.now() / 1000) - 600},v1=${"0".repeat(64)}`;
    expect((await call("/user", "{}", { header: stale })).status).toBe(401);
    expect((await call("/user", "{}", { method: "GET" })).status).toBe(405);
  });
});

// ---------------------------------------------------------------------------
// verifyAccessToken: keys and claims

describe("verifyAccessToken keys and claims", () => {
  async function tenant() {
    const issuer = unique("k");
    const keyPair = async () => (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const pairs: Record<string, CryptoKeyPair> = { k1: await keyPair(), k2: await keyPair() };
    const published = ["k1"];
    let jwksStatus = 200;
    const { fetcher, calls } = router({
      [`GET ${issuer}/.well-known/openid-configuration`]: discovery(issuer),
      [`GET ${issuer}/.well-known/jwks.json`]: async () =>
        jwksStatus === 200 ? Response.json({ keys: await Promise.all(published.map(async (kid) => ({ ...(await crypto.subtle.exportKey("jwk", pairs[kid]!.publicKey)), kid, alg: "ES256" }))) }) : new Response("down", { status: jwksStatus }),
    });
    const now = Math.floor(Date.now() / 1000);
    const claims = { iss: issuer, sub: "usr_1", aud: ["https://api.acme.test", "https://other.acme.test"], scope: "a b", iat: now, exp: now + 300 };
    const sign = async (payload: Record<string, unknown>, kid = "k1", header: Record<string, unknown> = {}) => {
      const input = `${b64json({ alg: "ES256", typ: "at+jwt", kid, ...header })}.${b64json(payload)}`;
      const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pairs[kid]!.privateKey, new TextEncoder().encode(input)));
      return `${input}.${base64UrlEncode(sig)}`;
    };
    const jwksFetches = () => calls.filter((r) => r.url.endsWith("/jwks.json")).length;
    return { issuer, fetcher, claims, sign, published, jwksFetches, setJwksStatus: (s: number) => (jwksStatus = s) };
  }

  it("picks up a rotated-in key with one refetch, and does not refetch for junk kids", async () => {
    const t = await tenant();
    const opts = { issuer: t.issuer, fetch: t.fetcher };
    await verifyAccessToken(await t.sign(t.claims), opts);
    expect(t.jwksFetches()).toBe(1);
    t.published.push("k2");
    await expect(verifyAccessToken(await t.sign(t.claims, "k2"), opts)).resolves.toMatchObject({ sub: "usr_1" });
    expect(t.jwksFetches()).toBe(2);
    await expect(verifyAccessToken(await t.sign(t.claims, "k2", { kid: "junk" }), opts)).rejects.toThrow(/unknown signing key/);
    await expect(verifyAccessToken(await t.sign(t.claims, "k2", { kid: "junk" }), opts)).rejects.toThrow(/unknown signing key/);
    expect(t.jwksFetches()).toBe(3);
  });

  it("checks issuer, not-before, any-of audiences, token type and algorithm", async () => {
    const t = await tenant();
    const opts = { issuer: t.issuer, fetch: t.fetcher };
    await expect(verifyAccessToken(await t.sign(t.claims), { ...opts, audience: ["https://nope", "https://other.acme.test"], scope: ["a", "b"] })).resolves.toBeTruthy();
    await expect(verifyAccessToken(await t.sign({ ...t.claims, iss: `${t.issuer}x` }), opts)).rejects.toThrow(/issuer/);
    await expect(verifyAccessToken(await t.sign({ ...t.claims, nbf: t.claims.iat + 600 }), opts)).rejects.toThrow(/not yet valid/);
    await expect(verifyAccessToken(await t.sign({ ...t.claims, exp: t.claims.iat - 10 }), { ...opts, clockTolerance: 60 })).resolves.toBeTruthy();
    await expect(verifyAccessToken(await t.sign(t.claims, "k1", { typ: "JWT" }), opts)).rejects.toThrow(/not an access token/);
    await expect(verifyAccessToken(await t.sign(t.claims, "k1", { alg: "none" }), opts)).rejects.toThrow(/unsupported algorithm/);
    await expect(verifyAccessToken(await t.sign(t.claims, "k1", { alg: "RS256" }), opts)).rejects.toThrow(/does not match the key/);
    await expect(verifyAccessToken("not.a.jwt", opts)).rejects.toMatchObject({ code: "invalid_token", status: 401 });
    await expect(verifyAccessToken("", opts)).rejects.toMatchObject({ code: "invalid_token" });
  });

  it("reports an unreachable key set", async () => {
    const t = await tenant();
    t.setJwksStatus(503);
    await expect(verifyAccessToken(await t.sign(t.claims), { issuer: t.issuer, fetch: t.fetcher })).rejects.toMatchObject({ code: "jwks_unavailable", status: 503 });
  });
});
