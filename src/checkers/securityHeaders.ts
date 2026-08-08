import { Checker, Finding, Severity } from "../types";

interface HeaderRule {
  header: string;
  severity: Severity;
  title: string;
  recommendation: string;
}

const RULES: HeaderRule[] = [
  {
    header: "content-security-policy",
    severity: "medium",
    title: "Missing Content-Security-Policy header",
    recommendation:
      "Set a Content-Security-Policy to constrain script/style sources and mitigate XSS and data injection.",
  },
  {
    header: "x-content-type-options",
    severity: "low",
    title: "Missing X-Content-Type-Options header",
    recommendation: "Set 'X-Content-Type-Options: nosniff' to stop MIME-type sniffing.",
  },
  {
    header: "x-frame-options",
    severity: "medium",
    title: "Missing X-Frame-Options / frame-ancestors protection",
    recommendation:
      "Set 'X-Frame-Options: DENY' (or a CSP frame-ancestors directive) to prevent clickjacking.",
  },
  {
    header: "strict-transport-security",
    severity: "medium",
    title: "Missing Strict-Transport-Security (HSTS) header",
    recommendation:
      "On HTTPS sites, set 'Strict-Transport-Security' so browsers refuse to downgrade to HTTP.",
  },
  {
    header: "referrer-policy",
    severity: "low",
    title: "Missing Referrer-Policy header",
    recommendation:
      "Set a Referrer-Policy (e.g. 'strict-origin-when-cross-origin') to limit referrer leakage.",
  },
];

export const securityHeadersChecker: Checker = {
  name: "security-headers",
  category: "Security Headers",
  async run(ctx) {
    const findings: Finding[] = [];
    const res = await ctx.http.get("/");
    for (const rule of RULES) {
      // HSTS only meaningfully applies to HTTPS; downgrade severity on http targets.
      if (
        rule.header === "strict-transport-security" &&
        !ctx.baseUrl.startsWith("https")
      ) {
        continue;
      }
      if (!(rule.header in res.headers)) {
        findings.push({
          id: `missing-header:${rule.header}`,
          category: this.category,
          severity: rule.severity,
          title: rule.title,
          evidence: `GET ${res.url} returned status ${res.status} with no '${rule.header}' response header.`,
          recommendation: rule.recommendation,
          url: res.url,
        });
      }
    }
    return findings;
  },
};
