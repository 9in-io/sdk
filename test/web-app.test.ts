import { afterEach, describe, expect, it, vi } from "vitest";
import { WebAppAuth, verifyIdToken, type LoginTransaction } from "../src/server";
import { base64UrlEncode, sha256 } from "../src/util";

const b64json = (o: unknown) => base64UrlEncode(new TextEncoder().encode(JSON.stringify(o)));

function router(routes: Record<string, (req: Request) => Response | Promise<Response>>) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input as RequestInfo, init);
    const url = new URL(req.url);
    const handler = routes[`${req.method} ${url.origin}${url.pathname}`];
    return handler ? handler(req) : new Response("not found", { status: 404 });
  }) as unknown as typeof fetch;
}

/** A mock tenant that signs ID tokens with an RSA key and serves the OIDC endpoints. */
async function tenant(options: { secret?: string } = {}) {
  const issuer = `https://acme.9in.test/w${Math.random().toString(36).slice(2)}`;
  const pair = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = { ...(await crypto.subtle.exportKey("jwk", pair.publicKey)), kid: "k1", alg: "RS256", use: "sig" };
  const now = () => Math.floor(Date.now() / 1000);
  const idToken = async (claims: Record<string, unknown>, header: Record<string, unknown> = {}) => {
    const input = `${b64json({ alg: "RS256", typ: "JWT", kid: "k1", ...header })}.${b64json({ iss: issuer, aud: "app_1", sub: "usr_1", iat: now(), exp: now() + 300, ...claims })}`;
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, new TextEncoder().encode(input)));
    return `${input}.${base64UrlEncode(sig)}`;
  };
  const seen: { token: URLSearchParams[]; auth: (string | null)[]; revoked: string[] } = { token: [], auth: [], revoked: [] };
  let nonce = "";
  let challenge = "";
  const fetcher = router({
    [`GET ${issuer}/.well-known/openid-configuration`]: () =>
      Response.json({
        issuer,
        authorization_endpoint: `${issuer}/oauth/authorize`,
        token_endpoint: `${issuer}/oauth/token`,
        userinfo_endpoint: `${issuer}/oauth/userinfo`,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
        end_session_endpoint: `${issuer}/oauth/logout`,
        revocation_endpoint: `${issuer}/oauth/revoke`,
      }),
    [`GET ${issuer}/.well-known/jwks.json`]: () => Response.json({ keys: [jwk] }),
    [`POST ${issuer}/oauth/token`]: async (req) => {
      const form = new URLSearchParams(await req.text());
      seen.token.push(form);
      seen.auth.push(req.headers.get("authorization"));
      if (options.secret && req.headers.get("authorization") !== `Basic ${btoa(`app_1:${options.secret}`)}`) return Response.json({ error: "invalid_client" }, { status: 401 });
      if (form.get("grant_type") === "authorization_code") {
        if (form.get("code") !== "code-1") return Response.json({ error: "invalid_grant" }, { status: 400 });
        if (base64UrlEncode(await sha256(form.get("code_verifier")!)) !== challenge) return Response.json({ error: "invalid_grant", error_description: "PKCE" }, { status: 400 });
        return Response.json({ access_token: "at-1", refresh_token: "rt-1", expires_in: 300, scope: "openid email", token_type: "Bearer", id_token: await idToken({ nonce, email: "jane@acme.test", amr: ["pwd", "mfa", "otp"] }) });
      }
      if (form.get("grant_type") === "refresh_token") return Response.json({ access_token: "at-2", expires_in: 300, token_type: "Bearer" });
      return Response.json({ error: "unsupported_grant_type" }, { status: 400 });
    },
    [`POST ${issuer}/oauth/revoke`]: async (req) => {
      seen.revoked.push(new URLSearchParams(await req.text()).get("token")!);
      return new Response(null, { status: 200 });
    },
    [`GET ${issuer}/oauth/userinfo`]: (req) => (req.headers.get("authorization") === "Bearer at-1" ? Response.json({ sub: "usr_1", name: "Jane" }) : new Response(null, { status: 401 })),
  });
  /** What 9in would do on the authorize endpoint: remember the nonce and challenge. */
  const authorize = (url: string) => {
    const params = new URL(url).searchParams;
    nonce = params.get("nonce")!;
    challenge = params.get("code_challenge")!;
    return params;
  };
  return { issuer, fetcher, idToken, seen, authorize };
}

afterEach(() => vi.restoreAllMocks());

describe("WebAppAuth", () => {
  it("signs in a confidential app: PKCE, client secret, verified ID token, refresh, logout", async () => {
    const t = await tenant({ secret: "s3cret" });
    const auth = new WebAppAuth({ issuer: t.issuer, clientId: "app_1", clientSecret: "s3cret", redirectUri: "https://app.acme.test/auth/callback", fetch: t.fetcher });
    const { url, transaction } = await auth.createLogin({ returnTo: "/dashboard", screen: "signup", locale: "de", params: { state: "evil", foo: "bar" } });
    const params = t.authorize(url);
    expect(params.get("response_type")).toBe("code");
    expect(params.get("client_id")).toBe("app_1");
    expect(params.get("prompt")).toBe("create");
    expect(params.get("ui_locales")).toBe("de");
    expect(params.get("foo")).toBe("bar");
    expect(params.get("state")).toBe(transaction.state);
    expect(params.get("code_challenge_method")).toBe("S256");
    expect(params.get("scope")).toBe("openid profile email offline_access");

    const result = await auth.handleCallback(`https://app.acme.test/auth/callback?code=code-1&state=${transaction.state}&iss=${encodeURIComponent(t.issuer)}`, transaction);
    expect(result.returnTo).toBe("/dashboard");
    expect(result.claims).toMatchObject({ sub: "usr_1", email: "jane@acme.test", amr: ["pwd", "mfa", "otp"] });
    expect(result.tokens).toMatchObject({ accessToken: "at-1", refreshToken: "rt-1", scope: "openid email" });
    expect(t.seen.token[0]!.get("client_id")).toBeNull(); // sent with HTTP Basic

    const refreshed = await auth.refresh("rt-1");
    expect(refreshed).toMatchObject({ accessToken: "at-2", refreshToken: "rt-1" });
    expect(await auth.userInfo("at-1")).toEqual({ sub: "usr_1", name: "Jane" });
    await auth.revoke("rt-1");
    expect(t.seen.revoked).toEqual(["rt-1"]);
    const logout = new URL(await auth.logoutUrl({ idTokenHint: result.tokens.idToken, postLogoutRedirectUri: "https://app.acme.test/" }));
    expect(logout.pathname.endsWith("/oauth/logout")).toBe(true);
    expect(logout.searchParams.get("post_logout_redirect_uri")).toBe("https://app.acme.test/");
    expect(logout.searchParams.get("id_token_hint")).toBe(result.tokens.idToken);
  });

  it("sends the client id in the body for public apps", async () => {
    const t = await tenant();
    const auth = new WebAppAuth({ issuer: t.issuer, clientId: "app_1", redirectUri: "https://app.acme.test/cb", fetch: t.fetcher });
    const { url, transaction } = await auth.createLogin();
    t.authorize(url);
    await auth.handleCallback(`https://app.acme.test/cb?code=code-1&state=${transaction.state}`, transaction);
    expect(t.seen.token[0]!.get("client_id")).toBe("app_1");
    expect(t.seen.auth[0]).toBeNull();
  });

  it("refuses errors, a missing or stale transaction, a wrong state or issuer, and a bad nonce", async () => {
    const t = await tenant();
    const auth = new WebAppAuth({ issuer: t.issuer, clientId: "app_1", redirectUri: "https://app.acme.test/cb", fetch: t.fetcher });
    const { url, transaction } = await auth.createLogin();
    t.authorize(url);
    const cb = (q: string) => `https://app.acme.test/cb?${q}`;
    await expect(auth.handleCallback(cb("error=access_denied&error_description=No"), transaction)).rejects.toMatchObject({ code: "access_denied" });
    await expect(auth.handleCallback(cb(`code=code-1&state=${transaction.state}`), null)).rejects.toMatchObject({ code: "invalid_state" });
    await expect(auth.handleCallback(cb(`code=code-1&state=other`), transaction)).rejects.toMatchObject({ code: "invalid_state" });
    await expect(auth.handleCallback(cb(`code=code-1&state=${transaction.state}&iss=https://evil.test`), transaction)).rejects.toMatchObject({ code: "invalid_issuer" });
    const stale: LoginTransaction = { ...transaction, createdAt: Date.now() - 16 * 60_000 };
    await expect(auth.handleCallback(cb(`code=code-1&state=${transaction.state}`), stale)).rejects.toMatchObject({ code: "invalid_state" });
    const tampered: LoginTransaction = { ...transaction, nonce: "other" };
    await expect(auth.handleCallback(cb(`code=code-1&state=${transaction.state}`), tampered)).rejects.toMatchObject({ code: "invalid_token" });
  });
});

describe("verifyIdToken", () => {
  it("checks signature, audience, azp, expiry, nonce and refuses access tokens", async () => {
    const t = await tenant();
    const options = { issuer: t.issuer, clientId: "app_1", fetch: t.fetcher };
    expect(await verifyIdToken(await t.idToken({ nonce: "n1" }), { ...options, nonce: "n1" })).toMatchObject({ sub: "usr_1" });
    await expect(verifyIdToken(await t.idToken({ aud: "other" }), options)).rejects.toThrow("audience mismatch");
    await expect(verifyIdToken(await t.idToken({ aud: ["app_1", "other"] }), options)).rejects.toThrow("authorized party");
    expect(await verifyIdToken(await t.idToken({ aud: ["app_1", "other"], azp: "app_1" }), options)).toMatchObject({ sub: "usr_1" });
    await expect(verifyIdToken(await t.idToken({ exp: Math.floor(Date.now() / 1000) - 120 }), options)).rejects.toThrow("expired");
    await expect(verifyIdToken(await t.idToken({ nonce: "n1" }), { ...options, nonce: "n2" })).rejects.toThrow("nonce");
    await expect(verifyIdToken(await t.idToken({}, { typ: "at+jwt" }), options)).rejects.toThrow("not an ID token");
    const token = await t.idToken({});
    await expect(verifyIdToken(`${token.slice(0, -4)}AAAA`, options)).rejects.toThrow();
  });
});
