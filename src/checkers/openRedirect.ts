import { Checker, Finding } from "../types";

/**
 * Benign open-redirect detector. We supply a harmless, obviously-external
 * sentinel URL as a redirect parameter and observe whether the app issues a
 * 3xx Location pointing to it. We use redirect: manual so we never actually
 * follow the redirect. No exploit, no credential handling — detection only.
 */
const SENTINEL = "https://authzswarm-benign.example.com/redirect-test";
const PATHS = ["/redirect", "/redir", "/go", "/out", "/login", "/logout"];
const PARAMS = ["url", "next", "redirect", "return", "returnUrl", "dest", "target"];

export const openRedirectChecker: Checker = {
  name: "open-redirect",
  category: "Open Redirect",
  async run(ctx) {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const path of PATHS) {
      for (const param of PARAMS) {
        const url = `${path}?${param}=${encodeURIComponent(SENTINEL)}`;
        let res;
        try {
          res = await ctx.http.get(url, { manualRedirect: true });
        } catch {
          continue;
        }
        if (res.status < 300 || res.status >= 400) continue;
        const loc = res.location ?? "";
        // Location points at our external sentinel host => open redirect.
        if (loc.includes("authzswarm-benign.example.com")) {
          const key = `${path}:${param}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push({
            id: `open-redirect:${path}:${param}`,
            category: this.category,
            severity: "medium",
            title: `Open redirect at ${path} (parameter "${param}")`,
            evidence: `GET ${res.url} returned ${res.status} with Location: ${loc} — an attacker-controlled external destination.`,
            recommendation:
              "Validate redirect targets against an allowlist of internal paths/hosts; never redirect to arbitrary user-supplied URLs.",
            url: res.url,
          });
        }
      }
    }
    return findings;
  },
};
