import { Checker, Finding } from "../types";

// Probe endpoints likely to trigger an error, plus a random non-existent path.
const PROBES = ["/error", "/?id[]=1", `/nonexistent-${Math.random().toString(36).slice(2, 8)}`];

const LEAK_SIGNATURES = [
  { rx: /at\s+.+\(.+:\d+:\d+\)/, what: "JavaScript/Node stack trace" },
  { rx: /Traceback \(most recent call last\)/, what: "Python traceback" },
  { rx: /Exception in thread|\bat [\w.$]+\([\w.]+\.java:\d+\)/, what: "Java stack trace" },
  { rx: /(SQLSTATE|SQL syntax|ORA-\d+|PG::)/i, what: "SQL error detail" },
  { rx: /\/Users\/|\/home\/|[A-Z]:\\\\/, what: "filesystem path" },
];

export const verboseErrorsChecker: Checker = {
  name: "verbose-errors",
  category: "Information Disclosure",
  async run(ctx) {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const path of PROBES) {
      let res;
      try {
        res = await ctx.http.get(path);
      } catch {
        continue;
      }
      // Only interested when the server actually errored or leaked on a 4xx/5xx.
      if (res.status < 400) continue;

      for (const sig of LEAK_SIGNATURES) {
        if (sig.rx.test(res.body)) {
          if (seen.has(sig.what)) continue;
          seen.add(sig.what);
          findings.push({
            id: `verbose-error:${sig.what.replace(/\s+/g, "-").toLowerCase()}`,
            category: this.category,
            severity: "medium",
            title: `Verbose error response leaks ${sig.what}`,
            evidence: `GET ${res.url} returned status ${res.status} containing a ${sig.what}. Snippet: ${res.body
              .slice(0, 160)
              .replace(/\s+/g, " ")
              .trim()}`,
            recommendation:
              "Return generic error pages in production and log details server-side. Do not expose stack traces, tracebacks, or filesystem paths to clients.",
            url: res.url,
          });
        }
      }
    }
    return findings;
  },
};
