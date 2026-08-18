import { Finding } from "./types";

/** Remove common credential forms before evidence reaches disk, terminal, or LLM triage. */
export function redactText(value: string, maxLength = 1_000): string {
  return value
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 [REDACTED]")
    .replace(/\b([A-Za-z0-9_]*(?:secret|token|password|passwd|api[_-]?key|session)[A-Za-z0-9_]*)\s*[:=]\s*([^\s,;]+)/gi, "$1=[REDACTED]")
    .replace(/(Set-Cookie:\s*[^=;,\s]+)=([^;,\s]*)/gi, "$1=[REDACTED]")
    .replace(/([?&](?:token|key|secret|password|pass|auth|session|code)=)[^&#\s]*/gi, "$1[REDACTED]")
    .slice(0, maxLength);
}

export function sanitizeFinding(finding: Finding): Finding {
  return {
    ...finding,
    evidence: redactText(finding.evidence),
    url: finding.url ? redactText(finding.url) : undefined,
  };
}
