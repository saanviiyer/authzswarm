import * as dns from "dns";
import * as http from "http";
import * as https from "https";
import * as net from "net";
import { HttpClient, HttpResponse } from "./types";

const MAX_BODY_BYTES = 200_000;
const MAX_REQUESTS = 100;
const MAX_REDIRECTS = 3;

/** A bounded, same-origin client whose DNS result is pinned for the whole scan. */
export class ThrottledHttpClient implements HttpClient {
  private readonly base: URL;
  private readonly concurrency: number;
  private readonly minDelayMs: number;
  private readonly timeoutMs: number;
  private readonly outerSignal?: AbortSignal;
  private readonly allowPrivateNetwork: boolean;
  private readonly userAgent = "AuthzSwarm/0.2 (authorized-defensive-security)";
  private active = 0;
  private queue: Array<{ resolve: () => void; reject: (err: Error) => void }> = [];
  private lastStart = 0;
  private rateGate: Promise<void> = Promise.resolve();
  private requestCount = 0;
  private closed = false;
  private pinnedAddress?: Promise<{ address: string; family: 4 | 6 }>;

  constructor(baseUrl: string, opts: {
    concurrency?: number; minDelayMs?: number; timeoutMs?: number; signal?: AbortSignal; allowPrivateNetwork?: boolean;
  } = {}) {
    this.base = new URL(baseUrl);
    this.concurrency = clampInteger(opts.concurrency ?? 2, 1, 8, "concurrency");
    this.minDelayMs = clampInteger(opts.minDelayMs ?? 250, 50, 10_000, "minimum delay");
    this.timeoutMs = clampInteger(opts.timeoutMs ?? 10_000, 1_000, 30_000, "timeout");
    this.outerSignal = opts.signal;
    this.allowPrivateNetwork = opts.allowPrivateNetwork === true;
    this.outerSignal?.addEventListener("abort", () => this.close("Scan cancelled"), { once: true });
  }

  async get(path: string, opts: { manualRedirect?: boolean } = {}): Promise<HttpResponse> {
    await this.acquire();
    try {
      this.throwIfClosed();
      if (++this.requestCount > MAX_REQUESTS) throw new Error(`Scan request limit (${MAX_REQUESTS}) exceeded`);
      await this.respectRateLimit();
      return await this.request(this.resolveUrl(path), Boolean(opts.manualRedirect), 0);
    } finally {
      this.release();
    }
  }

  close(reason = "HTTP client closed"): void {
    if (this.closed) return;
    this.closed = true;
    const error = new Error(reason);
    for (const waiter of this.queue.splice(0)) waiter.reject(error);
  }

  private resolveUrl(path: string): URL {
    const url = new URL(path, this.base);
    if (url.origin !== this.base.origin) throw new Error(`Refusing out-of-scope URL: ${redactUrl(url)}`);
    if (url.username || url.password) throw new Error("Refusing URL containing credentials");
    url.hash = "";
    return url;
  }

  private async request(url: URL, manualRedirect: boolean, redirects: number): Promise<HttpResponse> {
    this.throwIfClosed();
    const pinned = await (this.pinnedAddress ??= resolveAndValidate(this.base.hostname, this.allowPrivateNetwork));
    const transport = url.protocol === "https:" ? https : http;
    return await new Promise<HttpResponse>((resolve, reject) => {
      const controller = new AbortController();
      const abort = () => controller.abort(this.outerSignal?.reason ?? new Error("Scan cancelled"));
      this.outerSignal?.addEventListener("abort", abort, { once: true });
      const timer = setTimeout(() => controller.abort(new Error(`Request timed out after ${this.timeoutMs}ms`)), this.timeoutMs);
      const cleanup = () => {
        clearTimeout(timer);
        this.outerSignal?.removeEventListener("abort", abort);
      };
      const req = transport.request(url, {
        method: "GET",
        headers: { "user-agent": this.userAgent, accept: "*/*" },
        signal: controller.signal,
        lookup: (_hostname, options, callback) => {
          if (typeof options === "object" && options.all) {
            (callback as unknown as (err: null, addresses: Array<{ address: string; family: number }>) => void)(null, [pinned]);
          } else {
            (callback as unknown as (err: null, address: string, family: number) => void)(null, pinned.address, pinned.family);
          }
        },
      }, (res) => {
        const headers: Record<string, string> = {};
        for (const [key, value] of Object.entries(res.headers)) {
          if (value !== undefined) headers[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : value;
        }
        const chunks: Buffer[] = [];
        let bytes = 0;
        res.on("data", (chunk: Buffer) => {
          const remaining = MAX_BODY_BYTES - bytes;
          if (remaining > 0) chunks.push(chunk.subarray(0, remaining));
          bytes += chunk.length;
          if (bytes > MAX_BODY_BYTES) res.destroy(new Error(`Response exceeded ${MAX_BODY_BYTES} byte limit`));
        });
        res.on("end", async () => {
          cleanup();
          const status = res.statusCode ?? 0;
          const location = headers.location;
          if (!manualRedirect && location && status >= 300 && status < 400) {
            if (redirects >= MAX_REDIRECTS) return reject(new Error(`Redirect limit (${MAX_REDIRECTS}) exceeded`));
            let next: URL;
            try { next = new URL(location, url); } catch { return reject(new Error("Invalid redirect location")); }
            if (next.origin !== this.base.origin) return reject(new Error(`Refusing redirect outside authorized origin: ${redactUrl(next)}`));
            try { return resolve(await this.request(next, false, redirects + 1)); }
            catch (err) { return reject(err); }
          }
          resolve({ url: redactUrl(url), status, headers, body: Buffer.concat(chunks).toString("utf8"),
            redirected: redirects > 0 || (status >= 300 && status < 400), location });
        });
        res.on("error", (err) => { cleanup(); reject(err); });
      });
      req.on("error", (err) => { cleanup(); reject(err); });
      req.end();
    });
  }

  private acquire(): Promise<void> {
    this.throwIfClosed();
    if (this.active < this.concurrency) { this.active++; return Promise.resolve(); }
    return new Promise((resolve, reject) => this.queue.push({ resolve: () => { this.active++; resolve(); }, reject }));
  }

  private release(): void {
    this.active--;
    const next = this.queue.shift();
    if (next && !this.closed) next.resolve();
  }

  private async respectRateLimit(): Promise<void> {
    const previous = this.rateGate;
    let release!: () => void;
    this.rateGate = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try {
      const wait = this.lastStart + this.minDelayMs - Date.now();
      if (wait > 0) await abortableDelay(wait, this.outerSignal);
      this.lastStart = Date.now();
    } finally {
      release();
    }
  }

  private throwIfClosed(): void {
    if (this.closed || this.outerSignal?.aborted) throw new Error("Scan cancelled");
  }
}

async function resolveAndValidate(hostname: string, allowPrivateNetwork: boolean): Promise<{ address: string; family: 4 | 6 }> {
  const literalFamily = net.isIP(hostname);
  const results = literalFamily ? [{ address: hostname, family: literalFamily as 4 | 6 }]
    : await dns.promises.lookup(hostname, { all: true, verbatim: true });
  if (results.length === 0) throw new Error(`DNS returned no addresses for ${hostname}`);
  const localExplicit = hostname === "localhost" || literalFamily !== 0;
  if (!localExplicit && !allowPrivateNetwork && results.some((r) => isNonPublicAddress(r.address))) {
    throw new Error(`Refusing hostname resolving to a non-public address: ${hostname}`);
  }
  const chosen = results.find((result) => result.family === 4) ?? results[0];
  return { address: chosen.address, family: chosen.family as 4 | 6 };
}

export function isNonPublicAddress(address: string): boolean {
  if (address.includes(":")) {
    const ip = address.toLowerCase();
    if (ip.startsWith("::ffff:")) return isNonPublicAddress(ip.slice(7));
    return ip === "::" || ip === "::1" || ip.startsWith("fe8") || ip.startsWith("fe9") ||
      ip.startsWith("fea") || ip.startsWith("feb") || ip.startsWith("fc") || ip.startsWith("fd") ||
      ip.startsWith("ff") || ip.startsWith("2001:db8:") || ip.startsWith("2001:10:") || ip.startsWith("2001:2:");
  }
  const p = address.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  return p[0] === 0 || p[0] === 10 || p[0] === 127 || p[0] >= 224 ||
    (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && ((p[1] === 0 && (p[2] === 0 || p[2] === 2)) || p[1] === 168)) ||
    (p[0] === 100 && p[1] >= 64 && p[1] <= 127) ||
    (p[0] === 198 && (p[1] === 18 || p[1] === 19 || (p[1] === 51 && p[2] === 100))) ||
    (p[0] === 203 && p[1] === 0 && p[2] === 113);
}

function redactUrl(url: URL): string {
  const copy = new URL(url);
  for (const key of [...copy.searchParams.keys()]) {
    if (/token|key|secret|password|pass|auth|session|code/i.test(key)) copy.searchParams.set(key, "[REDACTED]");
  }
  return copy.toString();
}

function clampInteger(value: number, min: number, max: number, name: string): number {
  if (!Number.isInteger(value) || value < min || value > max) throw new Error(`${name} must be an integer from ${min} to ${max}`);
  return value;
}

function abortableDelay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const done = () => { signal?.removeEventListener("abort", abort); resolve(); };
    const timer = setTimeout(done, ms);
    const abort = () => { clearTimeout(timer); reject(new Error("Scan cancelled")); };
    signal?.addEventListener("abort", abort, { once: true });
  });
}
