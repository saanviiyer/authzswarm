#!/usr/bin/env node
import * as path from "path";
import { loadAllowlist, assertAuthorized, AllowlistError } from "./allowlist";
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

function parseArgs(argv: string[]): Args {
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
    else if (a === "--concurrency") args.concurrency = Number(rest[++i]);
    else if (a === "--delay") args.delay = Number(rest[++i]);
    else if (a === "--timeout") args.timeout = Number(rest[++i]);
    else if (a === "--out") args.outDir = rest[++i];
    else if (!a.startsWith("--") && !args.target) args.target = a;
  }
  return args;
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
  const args = parseArgs(process.argv.slice(2));

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
  try {
    const allowlist = loadAllowlist();
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
    await ensureAuthorizationAck({ flagPassed: args.iAmAuthorized });
  } catch (err) {
    process.stderr.write(`\n${(err as Error).message}\n\n`);
    process.exitCode = 4;
    return;
  }

  // 3. Run the swarm.
  const report = await runScan(baseUrl, {
    concurrency: args.concurrency,
    minDelayMs: args.delay,
    timeoutMs: args.timeout,
    triage: args.triage,
    onProgress: (msg) => process.stderr.write(`${msg}\n`),
  });

  // 4. Report.
  printReport(report);
  const paths = writeReports(report, args.outDir);
  process.stdout.write(`Wrote ${paths.json}\nWrote ${paths.html}\n`);

  // Non-zero exit if any high/critical finding, so CI can gate on it.
  if (report.summary.critical > 0 || report.summary.high > 0) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  process.stderr.write(`Fatal: ${(err as Error).stack ?? err}\n`);
  process.exitCode = 10;
});
