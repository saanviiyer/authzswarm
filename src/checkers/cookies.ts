import { Checker, Finding } from "../types";

export const cookiesChecker: Checker = {
  name: "cookie-flags",
  category: "Cookies",
  async run(ctx) {
    const findings: Finding[] = [];
    const res = await ctx.http.get("/");
    const setCookie = res.headers["set-cookie"];
    if (!setCookie) return findings;

    // Node's fetch may fold multiple Set-Cookie headers into one comma-joined
    // string; split conservatively on cookie boundaries.
    const cookies = setCookie.split(/,(?=[^;]+?=)/);
    for (const cookie of cookies) {
      const name = cookie.split("=")[0]?.trim() ?? "(unknown)";
      // Attributes are ';'-separated tokens after the name=value pair.
      const attrs = cookie
        .split(";")
        .slice(1)
        .map((a) => a.trim().toLowerCase());
      const missing: string[] = [];
      if (!attrs.includes("secure")) missing.push("Secure");
      if (!attrs.includes("httponly")) missing.push("HttpOnly");

      if (missing.length > 0) {
        findings.push({
          id: `insecure-cookie:${name}`,
          category: this.category,
          severity: missing.includes("HttpOnly") ? "medium" : "low",
          title: `Cookie "${name}" missing ${missing.join(" and ")} flag${
            missing.length > 1 ? "s" : ""
          }`,
          evidence: `Set-Cookie: ${name}=[REDACTED]; missing ${missing.join(" and ")}`,
          recommendation: `Set the ${missing.join(
            " and "
          )} attribute(s) on session/sensitive cookies to protect them from theft and script access.`,
          url: res.url,
        });
      }
    }
    return findings;
  },
};
