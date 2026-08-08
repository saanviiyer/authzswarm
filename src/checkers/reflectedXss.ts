import { Checker, Finding } from "../types";

/**
 * Benign reflected-input detector. We send a unique, harmless marker as a query
 * parameter and check whether it comes back UN-encoded in an HTML response.
 * This detects a *reflection point* (the precondition for reflected XSS). It
 * does NOT deliver an exploit payload — the marker contains angle brackets only
 * to test whether the app encodes them, which is the actual defensive control.
 */
const PATHS = ["/", "/search", "/q"];
const PARAMS = ["q", "search", "query", "s", "name"];

export const reflectedXssChecker: Checker = {
  name: "reflected-input",
  category: "Reflected Input / XSS",
  async run(ctx) {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const path of PATHS) {
      for (const param of PARAMS) {
        const marker = `azswarm${Math.random().toString(36).slice(2, 8)}`;
        // Angle brackets test whether the app HTML-encodes reflected input.
        const probe = `<${marker}>`;
        const url = `${path}?${param}=${encodeURIComponent(probe)}`;
        let res;
        try {
          res = await ctx.http.get(url);
        } catch {
          continue;
        }
        if (res.status >= 400) continue;
        const contentType = res.headers["content-type"] ?? "";
        if (!contentType.includes("html")) continue;

        // Un-encoded reflection: the raw "<marker>" appears verbatim in the body.
        if (res.body.includes(probe)) {
          const key = `${path}:${param}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push({
            id: `reflected-input:${path}:${param}`,
            category: this.category,
            severity: "high",
            title: `Un-encoded reflected input at ${path} (parameter "${param}")`,
            evidence: `Sent ${param}=${probe}; the raw value was reflected verbatim in the HTML response (angle brackets not encoded).`,
            recommendation:
              "HTML-encode all user-controlled values before rendering them into responses. This reflection point is exploitable as reflected XSS.",
            url: res.url,
          });
        }
      }
    }
    return findings;
  },
};
