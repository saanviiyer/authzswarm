import { Checker, Finding } from "../types";

/**
 * TLS/transport basics. This is a lightweight, non-intrusive check: it reports
 * whether the target is served over HTTPS and whether an HTTP endpoint upgrades
 * to HTTPS. It does not perform cipher/handshake fuzzing.
 */
export const tlsChecker: Checker = {
  name: "tls-basics",
  category: "Transport Security",
  async run(ctx) {
    const findings: Finding[] = [];

    if (!ctx.baseUrl.startsWith("https")) {
      findings.push({
        id: "transport:no-https",
        category: this.category,
        severity: "medium",
        title: "Target is served over plaintext HTTP",
        evidence: `Base URL ${ctx.baseUrl} uses HTTP; traffic (including cookies) is not encrypted in transit.`,
        recommendation:
          "Serve the application over HTTPS and redirect HTTP to HTTPS. (Expected for a local demo target; a finding for production hosts.)",
        url: ctx.baseUrl,
      });
    } else {
      // HTTPS target: confirm HSTS presence as a transport signal.
      const res = await ctx.http.get("/");
      if (!("strict-transport-security" in res.headers)) {
        findings.push({
          id: "transport:no-hsts",
          category: this.category,
          severity: "low",
          title: "HTTPS target without HSTS",
          evidence: `GET ${res.url} over HTTPS returned no Strict-Transport-Security header.`,
          recommendation:
            "Add a Strict-Transport-Security header so browsers refuse plaintext downgrades.",
          url: res.url,
        });
      }
    }
    return findings;
  },
};
