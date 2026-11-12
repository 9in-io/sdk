/**
 * 9in's request signature, as the 9in servers compute it (the reference the SDK must match):
 *
 *   9in-signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<METHOD>.<path>.<raw body>")>
 *
 * Tests sign with this what 9in would send, and check what the SDK sends back. (In 9in's own
 * repository, the server's implementation is also checked against the SDK directly.)
 */

const encoder = new TextEncoder();

function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

function payload(timestamp: number, method: string, path: string, body: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(`${timestamp}.${method.toUpperCase()}.${path}.${body}`);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(new ArrayBuffer(hex.length / 2));
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

async function sign(input: { secret: string; method: string; path: string; body: string; timestamp?: number }): Promise<string> {
  const timestamp = input.timestamp ?? Math.floor(Date.now() / 1000);
  const mac = await crypto.subtle.sign("HMAC", await hmacKey(input.secret), payload(timestamp, input.method, input.path, input.body));
  return `t=${timestamp},v1=${toHex(new Uint8Array(mac))}`;
}

async function verify(input: { secret: string; header: string | null | undefined; method: string; path: string; body: string }): Promise<{ ok: boolean }> {
  const match = /^t=(\d{1,12}),v1=([0-9a-f]{64})$/.exec(input.header ?? "");
  if (!match) return { ok: false };
  const timestamp = Number(match[1]);
  if (Math.abs(Math.floor(Date.now() / 1000) - timestamp) > 300) return { ok: false };
  const ok = await crypto.subtle.verify("HMAC", await hmacKey(input.secret), fromHex(match[2]!), payload(timestamp, input.method, input.path, input.body));
  return { ok };
}

export const signature = { sign, verify };
