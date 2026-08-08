import * as fs from "fs";
import * as path from "path";

export interface AllowlistFile {
  allowedTargets: string[];
}

export class AllowlistError extends Error {}

export function loadAllowlist(cwd = process.cwd()): string[] {
  const file = path.join(cwd, "authorized-targets.json");
  if (!fs.existsSync(file)) {
    throw new AllowlistError(
      `No authorized-targets.json found at ${file}. Create one listing ONLY hosts you own or are authorized to test.`
    );
  }
  let parsed: AllowlistFile;
  try {
    parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    throw new AllowlistError(`authorized-targets.json is not valid JSON: ${(e as Error).message}`);
  }
  if (!Array.isArray(parsed.allowedTargets)) {
    throw new AllowlistError(
      `authorized-targets.json must contain an "allowedTargets" array.`
    );
  }
  return parsed.allowedTargets.map((s) => s.trim().toLowerCase()).filter(Boolean);
}

/**
 * Hard gate. Returns the normalized base URL if authorized; throws otherwise.
 * A host is authorized if either its hostname OR its hostname:port appears in
 * the allowlist. This is DETECT-and-REPORT-against-authorized-targets only.
 */
export function assertAuthorized(rawTarget: string, allowlist: string[]): string {
  let url: URL;
  try {
    url = new URL(rawTarget.includes("://") ? rawTarget : `http://${rawTarget}`);
  } catch {
    throw new AllowlistError(`Target "${rawTarget}" is not a valid URL or host.`);
  }

  const host = url.hostname.toLowerCase();
  const hostPort = url.port ? `${host}:${url.port}` : host;

  const authorized =
    allowlist.includes(host) || allowlist.includes(hostPort);

  if (!authorized) {
    throw new AllowlistError(
      [
        `REFUSING TO SCAN: "${host}" is not on the allowlist.`,
        ``,
        `AuthzSwarm only scans hosts you have explicitly authorized in`,
        `authorized-targets.json. This is authorized-defensive-security tooling,`,
        `not a tool for testing systems you do not own.`,
        ``,
        `Currently allowed: ${allowlist.join(", ") || "(none)"}`,
        ``,
        `If you own or are authorized to test ${host}, add it to`,
        `authorized-targets.json and run again.`,
      ].join("\n")
    );
  }

  // Return a normalized base URL (scheme + host + optional port, no trailing slash).
  const scheme = url.protocol.replace(":", "") || "http";
  const portPart = url.port ? `:${url.port}` : "";
  return `${scheme}://${host}${portPart}`;
}
