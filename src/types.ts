export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export interface Finding {
  /** Stable identifier for this finding, e.g. "missing-header:content-security-policy". */
  id: string;
  category: string;
  severity: Severity;
  title: string;
  evidence: string;
  recommendation: string;
  url?: string;
}

export interface TriagedFinding extends Finding {
  /** 0-100 priority score assigned during triage (higher = fix sooner). */
  priority: number;
  triageNote: string;
}

export interface HttpResponse {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  redirected: boolean;
  location?: string;
}

export interface CheckerContext {
  /** Normalized target base URL, e.g. "http://localhost:3000". */
  baseUrl: string;
  http: HttpClient;
}

export interface Checker {
  name: string;
  category: string;
  run(ctx: CheckerContext): Promise<Finding[]>;
}

export interface HttpClient {
  get(
    path: string,
    opts?: { manualRedirect?: boolean }
  ): Promise<HttpResponse>;
}

export interface ScanReport {
  target: string;
  startedAt: string;
  finishedAt: string;
  checkersRun: string[];
  triageMode: "claude" | "mock";
  summary: Record<Severity, number>;
  findings: TriagedFinding[];
}
