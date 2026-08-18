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
import { redactText, sanitizeFinding } from "./redact";

export interface OrchestratorOptions {
  concurrency?: number;
  minDelayMs?: number;
  timeoutMs?: number;
  triage?: boolean;
  onProgress?: (msg: string) => void;
  signal?: AbortSignal;
  allowPrivateNetwork?: boolean;
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
    signal: opts.signal,
    allowPrivateNetwork: opts.allowPrivateNetwork,
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
        return { findings, error: undefined };
      } catch (err) {
        if (opts.signal?.aborted) throw err;
        log(`  [${checker.name}] error: ${(err as Error).message}`);
        return { findings: [] as Finding[], error: { checker: checker.name, message: sanitizeError(err) } };
      }
    })
  ).finally(() => http.close());

  const deduped = dedupe(results.flatMap((result) => result.findings).map(sanitizeFinding));
  const errors = results.flatMap((result) => result.error ? [result.error] : []);
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
    errors,
  };
}

function sanitizeError(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  return redactText(message.replace(/[\r\n]+/g, " "), 300);
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
