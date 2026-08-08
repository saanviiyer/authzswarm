import * as fs from "fs";
import * as path from "path";
import * as readline from "readline";

const ACK_FILE = ".authzswarm-ack.json";

interface AckRecord {
  acknowledged: boolean;
  acknowledgedAt: string;
  note: string;
}

export function hasAcknowledged(cwd = process.cwd()): boolean {
  const file = path.join(cwd, ACK_FILE);
  if (!fs.existsSync(file)) return false;
  try {
    const rec = JSON.parse(fs.readFileSync(file, "utf8")) as AckRecord;
    return rec.acknowledged === true;
  } catch {
    return false;
  }
}

export function recordAcknowledgement(cwd = process.cwd()): void {
  const file = path.join(cwd, ACK_FILE);
  const rec: AckRecord = {
    acknowledged: true,
    acknowledgedAt: new Date().toISOString(),
    note:
      "Operator confirmed they own or are explicitly authorized to test targets on the allowlist.",
  };
  fs.writeFileSync(file, JSON.stringify(rec, null, 2));
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
  cwd?: string;
}): Promise<void> {
  const cwd = opts.cwd ?? process.cwd();

  if (hasAcknowledged(cwd)) return;

  if (opts.flagPassed) {
    recordAcknowledgement(cwd);
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
      recordAcknowledgement(cwd);
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
