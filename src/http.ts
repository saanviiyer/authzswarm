import { HttpClient, HttpResponse } from "./types";

/**
 * A deliberately polite HTTP client.
 *
 * Two safety brakes are built in and cannot be removed without editing code:
 *   - a concurrency semaphore (default 2 in-flight requests), and
 *   - a minimum delay between request starts (default 250ms).
 *
 * Together these keep AuthzSwarm well below anything that could resemble a
 * denial-of-service, even against your own systems. Aggressive settings are the
 * operator's responsibility, on systems they own.
 */
export class ThrottledHttpClient implements HttpClient {
  private readonly baseUrl: string;
  private readonly concurrency: number;
  private readonly minDelayMs: number;
  private readonly timeoutMs: number;
  private readonly userAgent = "AuthzSwarm/0.1 (authorized-security-testing)";

  private active = 0;
  private queue: Array<() => void> = [];
  private lastStart = 0;

  constructor(
    baseUrl: string,
    opts: { concurrency?: number; minDelayMs?: number; timeoutMs?: number } = {}
  ) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.concurrency = Math.max(1, opts.concurrency ?? 2);
    this.minDelayMs = Math.max(0, opts.minDelayMs ?? 250);
    this.timeoutMs = Math.max(1000, opts.timeoutMs ?? 10000);
  }

  async get(
    path: string,
    opts: { manualRedirect?: boolean } = {}
  ): Promise<HttpResponse> {
    await this.acquire();
    try {
      await this.respectRateLimit();
      const url = path.startsWith("http")
        ? path
        : `${this.baseUrl}${path.startsWith("/") ? "" : "/"}${path}`;

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const res = await fetch(url, {
          method: "GET",
          redirect: opts.manualRedirect ? "manual" : "follow",
          headers: { "user-agent": this.userAgent },
          signal: controller.signal,
        });

        const headers: Record<string, string> = {};
        res.headers.forEach((value, key) => {
          headers[key.toLowerCase()] = value;
        });

        // Cap body size we read into memory; we only need a marker/snippet.
        const raw = await res.text();
        const body = raw.length > 200_000 ? raw.slice(0, 200_000) : raw;

        return {
          url,
          status: res.status,
          headers,
          body,
          redirected: res.redirected || (res.status >= 300 && res.status < 400),
          location: headers["location"],
        };
      } finally {
        clearTimeout(timer);
      }
    } finally {
      this.release();
    }
  }

  private acquire(): Promise<void> {
    if (this.active < this.concurrency) {
      this.active++;
      return Promise.resolve();
    }
    return new Promise((resolve) => {
      this.queue.push(() => {
        this.active++;
        resolve();
      });
    });
  }

  private release(): void {
    this.active--;
    const next = this.queue.shift();
    if (next) next();
  }

  private async respectRateLimit(): Promise<void> {
    const now = Date.now();
    const wait = this.lastStart + this.minDelayMs - now;
    if (wait > 0) {
      await new Promise((r) => setTimeout(r, wait));
    }
    this.lastStart = Date.now();
  }
}
