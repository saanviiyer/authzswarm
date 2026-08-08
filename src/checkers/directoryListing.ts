import { Checker, Finding } from "../types";

const CANDIDATES = ["/", "/backup/", "/files/", "/uploads/", "/static/", "/assets/"];

// Fingerprints emitted by common auto-index pages (Apache, nginx, Express serve-index).
const LISTING_SIGNATURES = [
  /Index of \//i,
  /<title>\s*Index of/i,
  /Directory listing for/i,
  /\[To Parent Directory\]/i,
];

export const directoryListingChecker: Checker = {
  name: "directory-listing",
  category: "Directory Listing",
  async run(ctx) {
    const findings: Finding[] = [];
    for (const path of CANDIDATES) {
      let res;
      try {
        res = await ctx.http.get(path);
      } catch {
        continue;
      }
      if (res.status !== 200) continue;
      if (LISTING_SIGNATURES.some((sig) => sig.test(res.body))) {
        findings.push({
          id: `directory-listing:${path}`,
          category: this.category,
          severity: "medium",
          title: `Directory listing enabled at ${path}`,
          evidence: `GET ${res.url} returned an auto-generated directory index, exposing file names.`,
          recommendation:
            "Disable automatic directory indexing so file listings are not exposed to visitors.",
          url: res.url,
        });
      }
    }
    return findings;
  },
};
