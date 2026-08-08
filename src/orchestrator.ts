import { CHECKERS } from "./checkers";
import { ThrottledHttpClient } from "./http";
import { triageFindings, sortTriaged } from "./triage";
import {
  Finding,
  ScanReport,
  Severity,
  TriagedFinding,
  CheckerContext,
} from "./types";

export interface OrchestratorOptions {
  concurrency?: number;
  minDelayMs?: number;
  timeoutMs?: number;
  triage?: boolean;
  onProgress?: (msg: string) => void;
}

/**
 * Runs the swarm: fans out every checker against the (already-authorized)
 * target, aggregates + dedupes findings, then triages and ranks them.
 */
export async function runScan(
  baseUrl: string,
  opts: OrchestratorOptions = {}
): Promise<ScanReport> {
  const startedAt = new Date().toISOString();
  const log = opts.onProgress ?? (() => {});

  const http = new ThrottledHttpClient(baseUrl, {
    concurrency: opts.concurrency,
    minDelayMs: opts.minDelayMs,
    timeoutMs: opts.timeoutMs,
  });
  const ctx: CheckerContext = { baseUrl, http };

  log(`Launching ${CHECKERS.length} checker agents against ${baseUrl}`);

  const results = await Promise.all(
    CHECKERS.map(async (checker) => {
      try {
        const findings = await checker.run(ctx);
        log(
          `  [${checker.name}] ${findings.length} finding${findings.length === 1 ? "" : "s"}`
        );
        return findings;
      } catch (err) {
        log(`  [${checker.name}] error: ${(err as Error).message}`);
        return [] as Finding[];
      }
    })
  );

  const deduped = dedupe(results.flat());
  log(`Aggregated ${deduped.length} unique finding(s).`);

  let triaged: TriagedFinding[];
  let triageMode: "claude" | "mock";
  if (opts.triage === false) {
    triaged = deduped.map((f) => ({
      ...f,
      priority: 0,
      triageNote: "Triage skipped (--no-triage).",
    }));
    triageMode = "mock";
  } else {
    log("Triaging findings...");
    const t = await triageFindings(deduped, baseUrl);
    triaged = t.findings;
    triageMode = t.mode;
    log(`Triage complete (mode: ${triageMode}).`);
  }

  triaged.sort(sortTriaged);

  return {
    target: baseUrl,
    startedAt,
    finishedAt: new Date().toISOString(),
    checkersRun: CHECKERS.map((c) => c.name),
    triageMode,
    summary: summarize(triaged),
    findings: triaged,
  };
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Map<string, Finding>();
  for (const f of findings) {
    if (!seen.has(f.id)) seen.set(f.id, f);
  }
  return [...seen.values()];
}

function summarize(findings: Finding[]): Record<Severity, number> {
  const summary: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) summary[f.severity]++;
  return summary;
}
