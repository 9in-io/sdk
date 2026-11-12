import { NineError, base64UrlEncode, decodeJwt, discover, normalizeIssuer, postForm, randomString, sha256 } from "./util.js";

export { NineError, normalizeIssuer } from "./util.js";

/**
 * Browser sign-in for single-page apps (also works in React Native / Electron with a
 * custom `storage` and `navigate`). Authorization code flow with PKCE, automatic
 * refresh-token rotation, RP-initiated logout.
 *
 *   const auth = new NineAuth({ issuer, clientId, redirectUri });
 *   await auth.login();               // redirect to the hosted login
 *   await auth.handleRedirect();      // on the callback page
 *   const user = await auth.getUser();
 *   const token = await auth.getAccessToken();
 */

export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface NineAuthOptions {
  /** Your tenant's issuer, e.g. https://acme.9in.io or https://login.acme.com */
  issuer: string;
  clientId: string;
  redirectUri: string;
  /** Default: "openid profile email offline_access". */
  scope?: string;
  /** API identifier to request access tokens for (aud claim). */
  audience?: string;
  /** Where tokens are kept. Default: localStorage (falls back to memory). */
  storage?: StorageLike;
  /** Where the PKCE verifier and state are kept during the redirect. Default: sessionStorage. */
  transientStorage?: StorageLike;
  /** Navigation hook (default: window.location.assign). */
  navigate?: (url: string) => void;
  /** Custom fetch (tests, React Native). */
  fetch?: typeof fetch;
  /** Language of the hosted pages (ui_locales). */
  locale?: string;
  /** Accept a plain-http issuer other than localhost (development only). */
  allowInsecureIssuer?: boolean;
}

export interface LoginOptions {
  /** "login" forces re-authentication, "consent" re-asks for consent, "none" fails instead of showing UI. */
  prompt?: "login" | "consent" | "none" | "select_account";
  /** Pre-fill the identifier field. */
  loginHint?: string;
  /** Open the sign-up form directly (prompt=create). */
  screen?: "login" | "signup";
  /** Where to send the user after handleRedirect (returned to you). */
  returnTo?: string;
  /** Extra authorization parameters. */
  params?: Record<string, string>;
}

export interface TokenSet {
  accessToken: string;
  idToken: string | null;
  refreshToken: string | null;
  /** ms since epoch */
  expiresAt: number;
  scope: string;
}

export interface User {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  phone_number?: string;
  locale?: string;
  [claim: string]: unknown;
}

class MemoryStorage implements StorageLike {
  private map = new Map<string, string>();
  getItem(key: string) {
    return this.map.get(key) ?? null;
  }
  setItem(key: string, value: string) {
    this.map.set(key, value);
  }
  removeItem(key: string) {
    this.map.delete(key);
  }
}

function defaultStorage(kind: "localStorage" | "sessionStorage"): StorageLike {
  try {
    const store = (globalThis as unknown as Record<string, StorageLike | undefined>)[kind];
    if (store) {
      store.setItem("__9in", "1");
      store.removeItem("__9in");
      return store;
    }
  } catch {
    // storage disabled (private mode, sandboxed iframe)
  }
  return new MemoryStorage();
}

interface PendingLogin {
  state: string;
  nonce: string;
  verifier: string;
  returnTo?: string;
}

export class NineAuth {
  private readonly issuer: string;
  private readonly storage: StorageLike;
  private readonly transient: StorageLike;
  private readonly fetcher: typeof fetch;
  private readonly key: string;
  private refreshing: Promise<TokenSet | null> | null = null;

  constructor(private readonly options: NineAuthOptions) {
    if (!options.issuer || !options.clientId || !options.redirectUri) throw new NineError("invalid_options", "issuer, clientId and redirectUri are required");
    this.issuer = normalizeIssuer(options.issuer, options.allowInsecureIssuer);
    this.storage = options.storage ?? defaultStorage("localStorage");
    this.transient = options.transientStorage ?? defaultStorage("sessionStorage");
    this.fetcher = options.fetch ?? fetch.bind(globalThis);
    this.key = `9in:${this.issuer}:${options.clientId}`;
  }

  private navigate(url: string) {
    if (this.options.navigate) this.options.navigate(url);
    else window.location.assign(url);
  }

  /** Builds the authorization URL and stores the PKCE verifier; `login()` navigates to it. */
  async buildLoginUrl(options: LoginOptions = {}): Promise<string> {
    const config = await discover(this.issuer, this.fetcher);
    const pending: PendingLogin = { state: randomString(16), nonce: randomString(16), verifier: randomString(48), returnTo: options.returnTo };
    this.transient.setItem(`${this.key}:pending`, JSON.stringify(pending));
    const url = new URL(config.authorization_endpoint);
    const params: Record<string, string> = {
      response_type: "code",
      client_id: this.options.clientId,
      redirect_uri: this.options.redirectUri,
      scope: this.options.scope ?? "openid profile email offline_access",
      state: pending.state,
      nonce: pending.nonce,
      code_challenge: base64UrlEncode(await sha256(pending.verifier)),
      code_challenge_method: "S256",
      ...(this.options.audience ? { audience: this.options.audience } : {}),
      ...(this.options.locale ? { ui_locales: this.options.locale } : {}),
      ...(options.loginHint ? { login_hint: options.loginHint } : {}),
      ...(options.screen === "signup" ? { prompt: "create" } : options.prompt ? { prompt: options.prompt } : {}),
      ...options.params,
    };
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    return url.toString();
  }

  /** Redirects to the hosted login page. */
  async login(options: LoginOptions = {}): Promise<void> {
    this.navigate(await this.buildLoginUrl(options));
  }

  /** Opens the sign-up form directly. */
  async signup(options: Omit<LoginOptions, "screen"> = {}): Promise<void> {
    return this.login({ ...options, screen: "signup" });
  }

  /**
   * Completes sign-in on the callback page: checks state, exchanges the code with the PKCE
   * verifier and stores the tokens. Removes the code from the address bar.
   */
  async handleRedirect(url: string = typeof window !== "undefined" ? window.location.href : ""): Promise<{ user: User; returnTo?: string }> {
    const current = new URL(url);
    const params = current.searchParams;
    const raw = this.transient.getItem(`${this.key}:pending`);
    this.transient.removeItem(`${this.key}:pending`);
    if (params.get("error")) throw new NineError(params.get("error")!, params.get("error_description") ?? undefined);
    const code = params.get("code");
    if (!code) throw new NineError("missing_code", "no authorization code in the URL");
    if (!raw) throw new NineError("invalid_state", "no login in progress (opened in another tab?)");
    const pending = JSON.parse(raw) as PendingLogin;
    if (params.get("state") !== pending.state) throw new NineError("invalid_state", "state mismatch");
    const iss = params.get("iss");
    if (iss && iss.replace(/\/$/, "") !== this.issuer && !(await this.sameIssuer(iss))) throw new NineError("invalid_issuer", `unexpected issuer ${iss}`);

    const config = await discover(this.issuer, this.fetcher);
    const tokens = await postForm<Record<string, unknown>>(
      config.token_endpoint,
      { grant_type: "authorization_code", code, redirect_uri: this.options.redirectUri, client_id: this.options.clientId, code_verifier: pending.verifier },
      {},
      this.fetcher,
    );
    if (typeof tokens.id_token === "string") {
      // The ID token came straight from the token endpoint over TLS (OIDC Core 3.1.3.7):
      // its claims are checked; the signature check is for servers (verifyAccessToken).
      // Checked before anything is stored, so a refused sign-in leaves no tokens behind.
      let payload: Record<string, unknown>;
      try {
        payload = decodeJwt(tokens.id_token).payload;
      } catch {
        throw new NineError("invalid_id_token", "malformed ID token");
      }
      const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!aud.includes(this.options.clientId)) throw new NineError("invalid_id_token", "audience mismatch");
      if (payload.nonce !== pending.nonce) throw new NineError("invalid_id_token", "nonce mismatch");
    }
    this.store(tokens);
    if (typeof window !== "undefined" && window.history && url === window.location.href) {
      for (const p of ["code", "state", "iss", "session_state"]) current.searchParams.delete(p);
      window.history.replaceState(window.history.state, "", current.pathname + current.search + current.hash);
    }
    return { user: (await this.getUser())!, returnTo: pending.returnTo };
  }

  private async sameIssuer(iss: string): Promise<boolean> {
    const config = await discover(this.issuer, this.fetcher);
    return config.issuer.replace(/\/$/, "") === iss.replace(/\/$/, "");
  }

  private store(tokens: Record<string, unknown>, previous?: TokenSet | null): TokenSet {
    const set: TokenSet = {
      accessToken: String(tokens.access_token),
      idToken: typeof tokens.id_token === "string" ? tokens.id_token : (previous?.idToken ?? null),
      refreshToken: typeof tokens.refresh_token === "string" ? tokens.refresh_token : (previous?.refreshToken ?? null),
      expiresAt: Date.now() + Number(tokens.expires_in ?? 3600) * 1000,
      scope: String(tokens.scope ?? previous?.scope ?? ""),
    };
    this.storage.setItem(`${this.key}:tokens`, JSON.stringify(set));
    return set;
  }

  /** Stored tokens (possibly expired). */
  getTokens(): TokenSet | null {
    const raw = this.storage.getItem(`${this.key}:tokens`);
    if (!raw) return null;
    try {
      return JSON.parse(raw) as TokenSet;
    } catch {
      return null;
    }
  }

  /** True when there is a usable access token or a refresh token. */
  isAuthenticated(): boolean {
    const t = this.getTokens();
    return !!t && (t.expiresAt > Date.now() || !!t.refreshToken);
  }

  /** Claims of the signed-in user from the ID token, or null. */
  async getUser(): Promise<User | null> {
    const t = this.getTokens();
    if (!t?.idToken) return null;
    return decodeJwt(t.idToken).payload as User;
  }

  /** Fresh claims from the userinfo endpoint. */
  async fetchUserInfo(): Promise<User> {
    const config = await discover(this.issuer, this.fetcher);
    const res = await this.fetcher(config.userinfo_endpoint, { headers: { Authorization: `Bearer ${await this.getAccessToken()}` } });
    if (!res.ok) throw new NineError("userinfo_failed", `HTTP ${res.status}`, res.status);
    return (await res.json()) as User;
  }

  /**
   * A valid access token, refreshed (with rotation) when it expires within a minute.
   * Concurrent callers share one refresh. Throws `login_required` when signed out.
   */
  async getAccessToken(): Promise<string> {
    const t = this.getTokens();
    if (t && t.expiresAt - 60_000 > Date.now()) return t.accessToken;
    if (!t?.refreshToken) throw new NineError("login_required");
    this.refreshing ??= this.refresh(t).finally(() => {
      this.refreshing = null;
    });
    const next = await this.refreshing;
    if (!next) throw new NineError("login_required");
    return next.accessToken;
  }

  private async refresh(current: TokenSet): Promise<TokenSet | null> {
    const config = await discover(this.issuer, this.fetcher);
    try {
      const tokens = await postForm<Record<string, unknown>>(
        config.token_endpoint,
        { grant_type: "refresh_token", refresh_token: current.refreshToken!, client_id: this.options.clientId },
        {},
        this.fetcher,
      );
      return this.store(tokens, current);
    } catch (error) {
      if (error instanceof NineError && error.code === "invalid_grant") {
        this.storage.removeItem(`${this.key}:tokens`);
        return null;
      }
      throw error;
    }
  }

  /** fetch() with the access token attached. */
  async fetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    headers.set("Authorization", `Bearer ${await this.getAccessToken()}`);
    return this.fetcher(input, { ...init, headers });
  }

  /** Clears local tokens, revokes the refresh token and ends the 9in session. */
  async logout(options: { returnTo?: string; local?: boolean } = {}): Promise<void> {
    const t = this.getTokens();
    this.storage.removeItem(`${this.key}:tokens`);
    const config = await discover(this.issuer, this.fetcher);
    if (t?.refreshToken && config.revocation_endpoint) {
      await postForm(config.revocation_endpoint, { token: t.refreshToken, token_type_hint: "refresh_token", client_id: this.options.clientId }, {}, this.fetcher).catch(() => undefined);
    }
    if (options.local) return;
    const url = new URL(config.end_session_endpoint ?? `${this.issuer}/oauth/logout`);
    url.searchParams.set("client_id", this.options.clientId);
    if (t?.idToken) url.searchParams.set("id_token_hint", t.idToken);
    if (options.returnTo) url.searchParams.set("post_logout_redirect_uri", options.returnTo);
    this.navigate(url.toString());
  }
}
