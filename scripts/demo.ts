/**
 * One-command demo: starts the bundled vulnerable demo target, waits for it to
 * come up, runs the scanner against it, then shuts the target down.
 *
 *   npm run demo
 */
import { spawn } from "child_process";
import * as path from "path";
import { loadAllowlist, assertAuthorized, isPrivateNetworkAuthorized } from "../src/allowlist";
import { ensureAuthorizationAck } from "../src/ack";
import { runScan } from "../src/orchestrator";
import { printReport, writeReports } from "../src/report";

const PORT = Number(process.env.PORT || 3000);
const TARGET = `http://localhost:${PORT}`;

async function waitForTarget(url: string, timeoutMs = 15000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(1000) });
      if (res.status < 500) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`Demo target did not start within ${timeoutMs}ms`);
}

async function main(): Promise<void> {
  const parent = path.resolve(__dirname, "..");
  const repoRoot = path.basename(parent) === "dist" ? path.resolve(parent, "..") : parent;
  const serverPath = path.join(repoRoot, "dist", "demo-target", "server.js");

  process.stdout.write("Starting bundled vulnerable demo target...\n");
  const child = spawn(process.execPath, [serverPath], {
    cwd: repoRoot,
    env: { ...process.env, PORT: String(PORT) },
    stdio: ["ignore", "inherit", "inherit"],
  });

  const shutdown = () => {
    if (!child.killed) child.kill("SIGTERM");
  };
  process.on("exit", shutdown);
  process.on("SIGINT", () => {
    shutdown();
    process.exit(130);
  });

  try {
    await waitForTarget(TARGET);
    process.stdout.write(`Demo target is up at ${TARGET}\n\n`);

    // Same gates the CLI enforces, run programmatically for the demo.
    const allowlist = loadAllowlist(repoRoot);
    const baseUrl = assertAuthorized(TARGET, allowlist);
    // The demo is an authorized local target: acknowledge non-interactively.
    await ensureAuthorizationAck({ flagPassed: true, target: baseUrl, allowlist, cwd: repoRoot });

    const report = await runScan(baseUrl, {
      onProgress: (msg) => process.stderr.write(`${msg}\n`),
      allowPrivateNetwork: isPrivateNetworkAuthorized(baseUrl, allowlist),
    });
    printReport(report);

    const outDir = path.join(repoRoot, "reports", `demo-${Date.now()}`);
    const paths = writeReports(report, outDir);
    process.stdout.write(`\nWrote ${paths.json}\nWrote ${paths.html}\n`);
    process.stdout.write(
      `\nFound ${report.findings.length} finding(s): ` +
        `${report.summary.critical} critical, ${report.summary.high} high, ` +
        `${report.summary.medium} medium, ${report.summary.low} low.\n`
    );
    if (report.errors.length > 0) {
      throw new Error(`Demo scan incomplete: ${report.errors.length} checker(s) failed`);
    }
  } finally {
    shutdown();
  }
}

main().catch((err) => {
  process.stderr.write(`Demo failed: ${(err as Error).stack ?? err}\n`);
  process.exitCode = 1;
});
