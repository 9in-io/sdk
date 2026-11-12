import { NineError, base64UrlEncode, discover, normalizeIssuer, postForm, randomString, sha256 } from "./util.js";
import { verifyIdToken, type IdTokenClaims } from "./server.js";

/**
 * Sign-in for server-rendered web apps (authorization code + PKCE, with or without a client
 * secret), using only `fetch` and Web Crypto: it runs on Node 18+, Next.js (Node and Edge),
 * Cloudflare Workers, Deno and Bun. Framework packages keep the transaction and the session
 * (for example in encrypted cookies); this class does the protocol:
 *
 *   const { url, transaction } = await auth.createLogin({ returnTo: "/dashboard" });
 *   // keep `transaction` until the callback, redirect the browser to `url`
 *   const { tokens, claims, returnTo } = await auth.handleCallback(request.url, transaction);
 */

export interface WebAppAuthOptions {
  /** Your tenant's issuer URL, e.g. https://acme.9in.io. */
  issuer: string;
  clientId: string;
  /** For confidential applications: sent with HTTP Basic. Leave out for public ones (PKCE only). */
  clientSecret?: string;
  /** Your callback URL, as registered on the application. */
  redirectUri: string;
  /** Default "openid profile email offline_access" (offline_access gives a refresh token). */
  scope?: string;
  /** An API identifier, to get access tokens for that API. */
  audience?: string;
  /** Only for tenants that sign with a shared (HMAC) key. */
  idTokenSecret?: string;
  fetch?: typeof fetch;
  /** Allows http:// issuers other than localhost (never in production). */
  allowInsecureIssuer?: boolean;
}

export interface WebLoginOptions {
  /** A path in your app to come back to after sign-in. */
  returnTo?: string;
  prompt?: "login" | "consent" | "none" | "select_account" | "create";
  /** Prefills the identifier on the sign-in page. */
  loginHint?: string;
  /** "signup" opens the registration page. */
  screen?: "login" | "signup";
  /** Language of the hosted pages (ui_locales), e.g. "de". */
  locale?: string;
  /** Extra authorization parameters (they never replace state, nonce or PKCE). */
  params?: Record<string, string>;
}

/** What to keep between the redirect to 9in and the callback (store it encrypted; it's secret). */
export interface LoginTransaction {
  state: string;
  nonce: string;
  verifier: string;
  returnTo?: string;
  /** ms */
  createdAt: number;
}

export interface WebTokenSet {
  accessToken: string;
  idToken: string | null;
  refreshToken: string | null;
  /** ms */
  expiresAt: number;
  scope: string;
  tokenType: string;
}

export interface CallbackResult {
  tokens: WebTokenSet;
  /** The verified ID token's claims: the signed-in user. */
  claims: IdTokenClaims;
  returnTo?: string;
}

const TRANSACTION_TTL = 15 * 60_000;
const RESERVED = new Set(["response_type", "client_id", "redirect_uri", "state", "nonce", "code_challenge", "code_challenge_method", "scope"]);

interface TokenResponse {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  token_type?: string;
}

export class WebAppAuth {
  private readonly issuer: string;
  private readonly fetcher: typeof fetch;

  constructor(private readonly options: WebAppAuthOptions) {
    if (!options.clientId) throw new NineError("invalid_options", "clientId is required");
    if (!options.redirectUri) throw new NineError("invalid_options", "redirectUri is required");
    this.issuer = normalizeIssuer(options.issuer, options.allowInsecureIssuer);
    this.fetcher = options.fetch ?? fetch.bind(globalThis);
  }

  /** The URL to send the browser to, and the transaction to keep until the callback. */
  async createLogin(options: WebLoginOptions = {}): Promise<{ url: string; transaction: LoginTransaction }> {
    const config = await discover(this.issuer, this.fetcher);
    const transaction: LoginTransaction = {
      state: randomString(24),
      nonce: randomString(24),
      verifier: randomString(48),
      createdAt: Date.now(),
      ...(options.returnTo ? { returnTo: options.returnTo } : {}),
    };
    const url = new URL(config.authorization_endpoint);
    const params = url.searchParams;
    for (const [key, value] of Object.entries(options.params ?? {})) if (!RESERVED.has(key)) params.set(key, value);
    params.set("response_type", "code");
    params.set("client_id", this.options.clientId);
    params.set("redirect_uri", this.options.redirectUri);
    params.set("scope", this.options.scope ?? "openid profile email offline_access");
    params.set("state", transaction.state);
    params.set("nonce", transaction.nonce);
    params.set("code_challenge", base64UrlEncode(await sha256(transaction.verifier)));
    params.set("code_challenge_method", "S256");
    if (this.options.audience) params.set("audience", this.options.audience);
    const prompt = options.screen === "signup" ? "create" : options.prompt;
    if (prompt) params.set("prompt", prompt);
    if (options.loginHint) params.set("login_hint", options.loginHint);
    if (options.locale) params.set("ui_locales", options.locale);
    return { url: url.toString(), transaction };
  }

  /**
   * Finishes sign-in on your callback URL: checks the state against the transaction, exchanges
   * the code and verifies the ID token (signature, issuer, audience, expiry, nonce).
   */
  async handleCallback(callbackUrl: string | URL, transaction: LoginTransaction | null | undefined): Promise<CallbackResult> {
    const url = new URL(callbackUrl);
    const error = url.searchParams.get("error");
    if (error) throw new NineError(error, url.searchParams.get("error_description") ?? error, 400);
    if (!transaction) throw new NineError("invalid_state", "no sign-in in progress (it expired, or started in another browser)", 400);
    if (Date.now() - transaction.createdAt > TRANSACTION_TTL) throw new NineError("invalid_state", "the sign-in took too long; start again", 400);
    if (url.searchParams.get("state") !== transaction.state) throw new NineError("invalid_state", "state mismatch", 400);
    // RFC 9207: when the issuer says who it is, it must be ours.
    const iss = url.searchParams.get("iss");
    if (iss && iss.replace(/\/$/, "") !== this.issuer) throw new NineError("invalid_issuer", `unexpected issuer ${iss}`, 400);
    const code = url.searchParams.get("code");
    if (!code) throw new NineError("missing_code", "no authorization code in the URL", 400);
    const tokens = await this.tokenRequest({ grant_type: "authorization_code", code, redirect_uri: this.options.redirectUri, code_verifier: transaction.verifier });
    const claims = await verifyIdToken(tokens.idToken, {
      issuer: this.issuer,
      clientId: this.options.clientId,
      nonce: transaction.nonce,
      secret: this.options.idTokenSecret,
      fetch: this.fetcher,
      allowInsecureIssuer: this.options.allowInsecureIssuer,
    });
    return { tokens, claims, ...(transaction.returnTo ? { returnTo: transaction.returnTo } : {}) };
  }

  /** New tokens from a refresh token (9in rotates it: keep the one returned). */
  async refresh(refreshToken: string): Promise<WebTokenSet> {
    const tokens = await this.tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken });
    return { ...tokens, refreshToken: tokens.refreshToken ?? refreshToken };
  }

  /** The URL that ends the session at 9in and comes back to `postLogoutRedirectUri`. */
  async logoutUrl(options: { idTokenHint?: string | null; postLogoutRedirectUri?: string; state?: string } = {}): Promise<string> {
    const config = await discover(this.issuer, this.fetcher);
    const url = new URL(config.end_session_endpoint ?? `${this.issuer}/logout`);
    url.searchParams.set("client_id", this.options.clientId);
    if (options.idTokenHint) url.searchParams.set("id_token_hint", options.idTokenHint);
    if (options.postLogoutRedirectUri) url.searchParams.set("post_logout_redirect_uri", options.postLogoutRedirectUri);
    if (options.state) url.searchParams.set("state", options.state);
    return url.toString();
  }

  /** Revokes a refresh token (ending the session's token family) or an access token. */
  async revoke(token: string, hint: "refresh_token" | "access_token" = "refresh_token"): Promise<void> {
    const config = await discover(this.issuer, this.fetcher);
    if (!config.revocation_endpoint) return;
    const { form, headers } = this.clientAuth({ token, token_type_hint: hint });
    await postForm(config.revocation_endpoint, form, headers, this.fetcher);
  }

  /** The user's current profile from the userinfo endpoint. */
  async userInfo(accessToken: string): Promise<Record<string, unknown>> {
    const config = await discover(this.issuer, this.fetcher);
    const res = await this.fetcher(config.userinfo_endpoint, { headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" } });
    if (!res.ok) throw new NineError(res.status === 401 ? "invalid_token" : "userinfo_failed", `HTTP ${res.status}`, res.status);
    return (await res.json()) as Record<string, unknown>;
  }

  private clientAuth(form: Record<string, string>): { form: Record<string, string>; headers: Record<string, string> } {
    if (!this.options.clientSecret) return { form: { ...form, client_id: this.options.clientId }, headers: {} };
    const basic = btoa(`${encodeURIComponent(this.options.clientId)}:${encodeURIComponent(this.options.clientSecret)}`);
    return { form, headers: { Authorization: `Basic ${basic}` } };
  }

  private async tokenRequest(input: Record<string, string>): Promise<WebTokenSet> {
    const config = await discover(this.issuer, this.fetcher);
    const { form, headers } = this.clientAuth(input);
    const json = await postForm<TokenResponse>(config.token_endpoint, form, headers, this.fetcher);
    return {
      accessToken: json.access_token,
      idToken: json.id_token ?? null,
      refreshToken: json.refresh_token ?? null,
      expiresAt: Date.now() + (json.expires_in ?? 3600) * 1000,
      scope: json.scope ?? "",
      tokenType: json.token_type ?? "Bearer",
    };
  }
}
