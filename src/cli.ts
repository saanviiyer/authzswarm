#!/usr/bin/env node
import * as path from "path";
import { loadAllowlist, assertAuthorized, isPrivateNetworkAuthorized, AllowlistError } from "./allowlist";
import { ensureAuthorizationAck } from "./ack";
import { runScan } from "./orchestrator";
import { printReport, writeReports } from "./report";

interface Args {
  command: string;
  target?: string;
  concurrency: number;
  delay: number;
  timeout: number;
  triage: boolean;
  outDir: string;
  iAmAuthorized: boolean;
}

export function parseArgs(argv: string[]): Args {
  const args: Args = {
    command: argv[0] ?? "help",
    concurrency: 2,
    delay: 250,
    timeout: 10000,
    triage: true,
    outDir: path.join("reports", `scan-${Date.now()}`),
    iAmAuthorized: false,
  };
  const rest = argv.slice(1);
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === "--i-am-authorized") args.iAmAuthorized = true;
    else if (a === "--no-triage") args.triage = false;
    else if (a === "--concurrency") args.concurrency = readNumber(rest, ++i, a, 1, 8);
    else if (a === "--delay") args.delay = readNumber(rest, ++i, a, 50, 10_000);
    else if (a === "--timeout") args.timeout = readNumber(rest, ++i, a, 1_000, 30_000);
    else if (a === "--out") {
      if (!rest[++i]) throw new Error("--out requires a directory");
      args.outDir = rest[i];
    }
    else if (a.startsWith("--")) throw new Error(`Unknown option: ${a}`);
    else if (!args.target) args.target = a;
    else throw new Error(`Unexpected argument: ${a}`);
  }
  return args;
}

function readNumber(rest: string[], i: number, name: string, min: number, max: number): number {
  const value = Number(rest[i]);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max}`);
  }
  return value;
}

function printHelp(): void {
  process.stdout.write(
    `
AuthzSwarm — authorized, multi-agent web security testing harness

  AUTHORIZED-USE ONLY. Run only against systems you own or are explicitly
  authorized to test. Targets must be on the authorized-targets.json allowlist.

Usage:
  authzswarm scan <target-url> [options]

Options:
  --i-am-authorized     Confirm authorization (recorded once in .authzswarm-ack.json)
  --concurrency <n>     Max concurrent requests (default 2)
  --delay <ms>          Min delay between requests in ms (default 250)
  --timeout <ms>        Per-request timeout in ms (default 10000)
  --no-triage           Skip the triage/prioritization step
  --out <dir>           Output directory for report.json/report.html
                        (default reports/scan-<timestamp>)

Examples:
  npm run demo:target                 # start the bundled vulnerable demo app
  authzswarm scan http://localhost:3000 --i-am-authorized
  npm run scan -- http://localhost:3000 --i-am-authorized

The default allowlist contains only localhost and the bundled demo target.
`
  );
}

async function main(): Promise<void> {
  let args: Args;
  try { args = parseArgs(process.argv.slice(2)); }
  catch (err) {
    process.stderr.write(`Error: ${(err as Error).message}\n`);
    process.exitCode = 2;
    return;
  }

  if (args.command === "help" || args.command === "--help" || args.command === "-h") {
    printHelp();
    return;
  }

  if (args.command !== "scan") {
    process.stderr.write(`Unknown command: ${args.command}\n`);
    printHelp();
    process.exitCode = 2;
    return;
  }

  if (!args.target) {
    process.stderr.write("Error: a target URL is required.\n\n");
    printHelp();
    process.exitCode = 2;
    return;
  }

  // 1. Allowlist gate (hard refuse for non-allowlisted hosts).
  let baseUrl: string;
  let allowlist: string[];
  try {
    allowlist = loadAllowlist();
    baseUrl = assertAuthorized(args.target, allowlist);
  } catch (err) {
    if (err instanceof AllowlistError) {
      process.stderr.write(`\n${err.message}\n\n`);
      process.exitCode = 3;
      return;
    }
    throw err;
  }

  // 2. Authorization acknowledgement (first run / --i-am-authorized).
  try {
    await ensureAuthorizationAck({ flagPassed: args.iAmAuthorized, target: baseUrl, allowlist });
  } catch (err) {
    process.stderr.write(`\n${(err as Error).message}\n\n`);
    process.exitCode = 4;
    return;
  }

  // 3. Run the swarm.
  const controller = new AbortController();
  const cancel = () => controller.abort(new Error("Scan cancelled by operator"));
  process.once("SIGINT", cancel);
  process.once("SIGTERM", cancel);
  const report = await runScan(baseUrl, {
    concurrency: args.concurrency,
    minDelayMs: args.delay,
    timeoutMs: args.timeout,
    triage: args.triage,
    onProgress: (msg) => process.stderr.write(`${msg}\n`),
    signal: controller.signal,
    allowPrivateNetwork: isPrivateNetworkAuthorized(baseUrl, allowlist),
  }).finally(() => {
    process.removeListener("SIGINT", cancel);
    process.removeListener("SIGTERM", cancel);
  });

  // 4. Report.
  printReport(report);
  const paths = writeReports(report, args.outDir);
  process.stdout.write(`Wrote ${paths.json}\nWrote ${paths.html}\n`);

  if (report.errors.length > 0) {
    process.stderr.write(`Scan incomplete: ${report.errors.length} checker(s) failed.\n`);
    process.exitCode = 5;
    return;
  }

  // Non-zero exit if any high/critical finding, so CI can gate on it.
  if (report.summary.critical > 0 || report.summary.high > 0) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  process.stderr.write(`Fatal: ${(err as Error).stack ?? err}\n`);
  process.exitCode = 10;
});
