/** Small, dependency-free helpers shared by the browser and server entry points. */

const enc = new TextEncoder();

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlDecode(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function randomString(bytes = 32): string {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function sha256(value: string): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(value)));
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function utf8(value: string): Uint8Array<ArrayBuffer> {
  return enc.encode(value) as Uint8Array<ArrayBuffer>;
}

export interface JwtParts {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: string;
  signature: Uint8Array<ArrayBuffer>;
}

export function decodeJwt(token: string): JwtParts {
  const parts = token.split(".");
  if (parts.length !== 3) throw new NineError("invalid_token", "not a JWT");
  const json = (s: string) => JSON.parse(new TextDecoder().decode(base64UrlDecode(s))) as Record<string, unknown>;
  return { header: json(parts[0]!), payload: json(parts[1]!), signingInput: `${parts[0]}.${parts[1]}`, signature: base64UrlDecode(parts[2]!) };
}

export class NineError extends Error {
  constructor(
    readonly code: string,
    message?: string,
    readonly status?: number,
  ) {
    super(message ? `${code}: ${message}` : code);
    this.name = "NineError";
  }
}

function isLocalHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return host === "localhost" || host.endsWith(".localhost") || host === "::1" || /^127(\.\d{1,3}){3}$/.test(host);
}

/**
 * Validates an issuer URL and drops a trailing slash. Issuers must use https; plain http
 * is accepted only for localhost, *.localhost and loopback addresses (development), or
 * when `allowInsecure` is set. Query strings, fragments and credentials are rejected.
 * Throws `NineError` (`invalid_issuer` / `insecure_issuer`).
 */
export function normalizeIssuer(issuer: string, allowInsecure = false): string {
  let url: URL;
  try {
    url = new URL(issuer);
  } catch {
    throw new NineError("invalid_issuer", `not a URL: ${issuer}`);
  }
  if (url.search || url.hash || url.username || url.password) throw new NineError("invalid_issuer", "an issuer has no query, fragment or credentials");
  const secure = url.protocol === "https:" || (url.protocol === "http:" && (allowInsecure || isLocalHostname(url.hostname)));
  if (!secure) throw new NineError("insecure_issuer", `issuer must use https (got ${url.protocol}//${url.host}); plain http is only accepted for localhost`);
  return issuer.replace(/\/$/, "");
}

const discoveryCache = new Map<string, Promise<Discovery>>();

export interface Discovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
  revocation_endpoint?: string;
  introspection_endpoint?: string;
  device_authorization_endpoint?: string;
}

export function discover(issuer: string, fetcher: typeof fetch = fetch): Promise<Discovery> {
  const key = issuer.replace(/\/$/, "");
  let hit = discoveryCache.get(key);
  if (!hit) {
    hit = fetcher(`${key}/.well-known/openid-configuration`).then(async (res) => {
      if (!res.ok) throw new NineError("discovery_failed", `HTTP ${res.status}`, res.status);
      return (await res.json()) as Discovery;
    });
    hit.catch(() => discoveryCache.delete(key));
    discoveryCache.set(key, hit);
  }
  return hit;
}

export async function postForm<T>(url: string, form: Record<string, string>, headers: Record<string, string> = {}, fetcher: typeof fetch = fetch): Promise<T> {
  const res = await fetcher(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json", ...headers },
    body: new URLSearchParams(form),
  });
  const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) throw new NineError(String(json.error ?? "request_failed"), json.error_description ? String(json.error_description) : `HTTP ${res.status}`, res.status);
  return json as T;
}
