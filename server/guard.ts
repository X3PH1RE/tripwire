import type { RequestHandler } from "express";

/**
 * The API can scan any folder on this machine, read the results back and, with `apply`, revoke keys. It has no login,
 * so it must only ever answer the local web app. Binding to 127.0.0.1 keeps the network out; these checks keep other
 * websites out (DNS rebinding sends the attacker's own Host, cross-site requests carry a foreign Origin).
 */
const LOCAL = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** `host[:port]` to its host part, IPv6 brackets kept. */
const hostOf = (hostHeader: string) => hostHeader.toLowerCase().replace(/:\d+$/, "");

export function hostAllowed(hostHeader: string | undefined, extra: string[] = []): boolean {
  if (!hostHeader) return false;
  const host = hostOf(hostHeader);
  return LOCAL.has(host) || extra.includes(host);
}

/** An absent Origin is a non-browser client (curl, the CLI) or a same-origin GET; a present one must be local. */
export function originAllowed(origin: string | undefined, extra: string[] = []): boolean {
  if (!origin) return true;
  try {
    return hostAllowed(new URL(origin).host, extra);
  } catch {
    return false;
  }
}

export function guard(extraHosts: string[] = (process.env.ALLOWED_HOSTS ?? "").split(",").map((h) => h.trim().toLowerCase()).filter(Boolean)): RequestHandler {
  return (req, res, next) => {
    const write = req.method !== "GET" && req.method !== "HEAD";
    const crossSite = req.headers["sec-fetch-site"] === "cross-site";
    if (!hostAllowed(req.headers.host, extraHosts) || !originAllowed(req.headers.origin, extraHosts) || (write && crossSite)) {
      res.status(403).json({ error: "Forbidden: this API only answers the local Tripwire app." });
      return;
    }
    next();
  };
}
