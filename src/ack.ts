import * as fs from "fs";
import * as path from "path";
import * as readline from "readline";
import { createHash } from "crypto";

const ACK_FILE = ".authzswarm-ack.json";

interface AckRecord {
  version: 2;
  acknowledged: boolean;
  acknowledgedAt: string;
  target: string;
  allowlistDigest: string;
  note: string;
}

function digestAllowlist(allowlist: string[]): string {
  return createHash("sha256").update([...allowlist].sort().join("\n")).digest("hex");
}

export function hasAcknowledged(target: string, allowlist: string[], cwd = process.cwd()): boolean {
  const file = path.join(cwd, ACK_FILE);
  if (!fs.existsSync(file)) return false;
  try {
    const rec = JSON.parse(fs.readFileSync(file, "utf8")) as AckRecord;
    return rec.version === 2 && rec.acknowledged === true && rec.target === target &&
      rec.allowlistDigest === digestAllowlist(allowlist);
  } catch {
    return false;
  }
}

export function recordAcknowledgement(target: string, allowlist: string[], cwd = process.cwd()): void {
  const file = path.join(cwd, ACK_FILE);
  const rec: AckRecord = {
    version: 2,
    acknowledged: true,
    acknowledgedAt: new Date().toISOString(),
    target,
    allowlistDigest: digestAllowlist(allowlist),
    note:
      "Operator confirmed they own or are explicitly authorized to test targets on the allowlist.",
  };
  const temp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(rec, null, 2), { mode: 0o600 });
  fs.renameSync(temp, file);
}

/**
 * Ensures the operator has confirmed authorization at least once.
 *
 * Order of precedence:
 *   1. A prior recorded acknowledgement (.authzswarm-ack.json) — silent pass.
 *   2. The --i-am-authorized flag — records the acknowledgement, then passes.
 *   3. An interactive TTY prompt — records on "yes".
 *   4. Otherwise: refuse (non-interactive, no flag, no prior ack).
 */
export async function ensureAuthorizationAck(opts: {
  flagPassed: boolean;
  target: string;
  allowlist: string[];
  cwd?: string;
}): Promise<void> {
  const cwd = opts.cwd ?? process.cwd();

  if (hasAcknowledged(opts.target, opts.allowlist, cwd)) return;

  if (opts.flagPassed) {
    recordAcknowledgement(opts.target, opts.allowlist, cwd);
    return;
  }

  if (process.stdin.isTTY && process.stdout.isTTY) {
    const answer = await prompt(
      [
        "AUTHORIZATION REQUIRED",
        "",
        "AuthzSwarm sends active security probes to the target. Only run it",
        "against systems you OWN or are EXPLICITLY AUTHORIZED to test.",
        "",
        "Do you confirm you are authorized to test the allowlisted target(s)? (yes/no) ",
      ].join("\n")
    );
    if (answer.trim().toLowerCase() === "yes" || answer.trim().toLowerCase() === "y") {
      recordAcknowledgement(opts.target, opts.allowlist, cwd);
      return;
    }
    throw new Error("Authorization not confirmed. Aborting.");
  }

  throw new Error(
    [
      "Authorization has not been acknowledged.",
      "Re-run with the --i-am-authorized flag to confirm you own or are",
      "explicitly authorized to test the allowlisted target(s). This is",
      "recorded once in .authzswarm-ack.json.",
    ].join("\n")
  );
}

function prompt(question: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}
