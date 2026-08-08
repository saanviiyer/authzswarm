import { Checker, Finding, Severity } from "../types";

interface PathRule {
  path: string;
  severity: Severity;
  title: string;
  /** A substring that, if present in a 200 body, strongly indicates real exposure. */
  signature?: RegExp;
  recommendation: string;
}

const RULES: PathRule[] = [
  {
    path: "/.env",
    severity: "critical",
    title: "Exposed .env file",
    signature: /[A-Z0-9_]+=/,
    recommendation:
      "Never serve .env files. Block dotfiles at the web server and keep secrets out of the web root.",
  },
  {
    path: "/.git/config",
    severity: "high",
    title: "Exposed .git repository metadata",
    signature: /\[core\]|\[remote|repositoryformatversion/i,
    recommendation:
      "Block access to .git directories. An exposed repo can leak source code and history.",
  },
  {
    path: "/backup.zip",
    severity: "high",
    title: "Exposed backup archive",
    recommendation: "Remove backup archives from the web root and block archive extensions.",
  },
  {
    path: "/.aws/credentials",
    severity: "critical",
    title: "Exposed AWS credentials file",
    signature: /aws_access_key_id|aws_secret_access_key/i,
    recommendation: "Never store cloud credentials in the web root; block dotfiles.",
  },
  {
    path: "/config.json",
    severity: "medium",
    title: "Exposed config.json",
    signature: /[{[]/,
    recommendation:
      "Ensure config files served publicly contain no secrets; move sensitive config out of the web root.",
  },
];

export const exposedPathsChecker: Checker = {
  name: "exposed-paths",
  category: "Exposed Files / Paths",
  async run(ctx) {
    const findings: Finding[] = [];
    for (const rule of RULES) {
      let res;
      try {
        res = await ctx.http.get(rule.path);
      } catch {
        continue;
      }
      if (res.status !== 200) continue;
      // If a signature is defined, require it to reduce false positives from
      // SPA catch-all routes that return 200 for everything.
      if (rule.signature && !rule.signature.test(res.body)) continue;

      findings.push({
        id: `exposed-path:${rule.path}`,
        category: this.category,
        severity: rule.severity,
        title: rule.title,
        evidence: `GET ${res.url} returned 200 (${res.body.length} bytes). Snippet: ${res.body
          .slice(0, 120)
          .replace(/\s+/g, " ")
          .trim()}`,
        recommendation: rule.recommendation,
        url: res.url,
      });
    }
    return findings;
  },
};
