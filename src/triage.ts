import { Finding, TriagedFinding, Severity, SEVERITY_ORDER } from "./types";

const DEFAULT_MODEL = process.env.AUTHZSWARM_TRIAGE_MODEL || "claude-sonnet-5";

// Deterministic base priority derived from severity (higher = fix sooner).
const SEVERITY_BASE: Record<Severity, number> = {
  critical: 95,
  high: 80,
  medium: 55,
  low: 30,
  info: 10,
};

export interface TriageResult {
  mode: "claude" | "mock";
  findings: TriagedFinding[];
}

/**
 * LLM-assisted triage. If ANTHROPIC_API_KEY is set, Claude summarizes and
 * re-prioritizes the findings. Otherwise we fall back to deterministic MOCK
 * MODE so the tool runs end-to-end with zero setup. Any per-finding gap in the
 * model's response is backfilled from the mock scoring, so triage never drops
 * a finding.
 */
export async function triageFindings(
  findings: Finding[],
  target: string
): Promise<TriageResult> {
  if (findings.length === 0) {
    return { mode: process.env.ANTHROPIC_API_KEY ? "claude" : "mock", findings: [] };
  }

  if (!process.env.ANTHROPIC_API_KEY) {
    return { mode: "mock", findings: findings.map(mockTriage) };
  }

  try {
    const claude = await claudeTriage(findings, target);
    return { mode: "claude", findings: claude };
  } catch (err) {
    process.stderr.write(
      `[triage] Claude triage failed (${(err as Error).message}); falling back to mock mode.\n`
    );
    return { mode: "mock", findings: findings.map(mockTriage) };
  }
}

function mockTriage(f: Finding): TriagedFinding {
  return {
    ...f,
    priority: SEVERITY_BASE[f.severity],
    triageNote: `Prioritized by severity (${f.severity}). Set ANTHROPIC_API_KEY for Claude-assisted triage.`,
  };
}

async function claudeTriage(
  findings: Finding[],
  target: string
): Promise<TriagedFinding[]> {
  // Lazy import so the tool runs without the SDK installed in mock mode.
  const Anthropic = (await import("@anthropic-ai/sdk")).default;
  const client = new Anthropic();

  const system =
    "You are a defensive application-security triage assistant. You are given " +
    "structured findings from an AUTHORIZED scan of the operator's own web app. " +
    "For each finding, assign a priority from 0-100 (higher = fix sooner), " +
    "considering severity, exploitability, and real-world impact, and write a " +
    "one-sentence, actionable triage note. Respond with ONLY a JSON array of " +
    'objects: [{"id": string, "priority": number, "note": string}]. No prose.';

  const compact = findings.map((f) => ({
    id: f.id,
    category: f.category,
    severity: f.severity,
    title: f.title,
    evidence: f.evidence,
  }));

  const message = await client.messages.create({
    model: DEFAULT_MODEL,
    max_tokens: 4096,
    system,
    messages: [
      {
        role: "user",
        content: `Target: ${target}\n\nFindings:\n${JSON.stringify(compact, null, 2)}`,
      },
    ],
  });

  const text = message.content
    .map((b) => (b.type === "text" ? b.text : ""))
    .join("\n");

  const parsed = parseJsonArray(text);
  const byId = new Map<string, { priority: number; note: string }>();
  for (const item of parsed) {
    if (item && typeof item.id === "string") {
      byId.set(item.id, {
        priority: clampScore(item.priority),
        note: typeof item.note === "string" ? item.note : "",
      });
    }
  }

  // Merge: use Claude's score/note where present, mock fallback otherwise.
  return findings.map((f) => {
    const t = byId.get(f.id);
    if (t) {
      return {
        ...f,
        priority: t.priority || SEVERITY_BASE[f.severity],
        triageNote: t.note || `Prioritized by severity (${f.severity}).`,
      };
    }
    return mockTriage(f);
  });
}

function clampScore(n: unknown): number {
  const v = typeof n === "number" ? n : Number(n);
  if (!Number.isFinite(v)) return 0;
  return Math.max(0, Math.min(100, Math.round(v)));
}

function parseJsonArray(text: string): Array<{ id?: unknown; priority?: unknown; note?: unknown }> {
  const start = text.indexOf("[");
  const end = text.lastIndexOf("]");
  if (start === -1 || end === -1 || end <= start) return [];
  try {
    const arr = JSON.parse(text.slice(start, end + 1));
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

/** Sort helper: by priority desc, then by severity, then title. */
export function sortTriaged(a: TriagedFinding, b: TriagedFinding): number {
  if (b.priority !== a.priority) return b.priority - a.priority;
  const sev = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
  if (sev !== 0) return sev;
  return a.title.localeCompare(b.title);
}
