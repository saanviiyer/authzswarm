import * as fs from "fs";
import * as path from "path";
import { ScanReport, Severity } from "./types";

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "\x1b[41m\x1b[97m",
  high: "\x1b[31m",
  medium: "\x1b[33m",
  low: "\x1b[36m",
  info: "\x1b[90m",
};
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";

/** Prints a ranked, colorized report to the terminal. */
export function printReport(report: ScanReport): void {
  const out = process.stdout;
  out.write(`\n${BOLD}AuthzSwarm findings for ${report.target}${RESET}\n`);
  out.write(
    `Triage mode: ${report.triageMode}  |  Checkers: ${report.checkersRun.length}  |  ${report.startedAt}\n`
  );

  const s = report.summary;
  out.write(
    `\nSummary: ${sev("critical", s.critical)}  ${sev("high", s.high)}  ${sev(
      "medium",
      s.medium
    )}  ${sev("low", s.low)}  ${sev("info", s.info)}\n`
  );

  if (report.findings.length === 0) {
    out.write(`\n${BOLD}No findings.${RESET}\n\n`);
    return;
  }

  out.write(`\n${BOLD}Findings (ranked by priority):${RESET}\n`);
  report.findings.forEach((f, i) => {
    const color = SEVERITY_COLORS[f.severity];
    out.write(
      `\n${BOLD}${i + 1}. ${f.title}${RESET}\n` +
        `   ${color} ${f.severity.toUpperCase()} ${RESET} priority ${f.priority}  |  ${f.category}\n` +
        `   ${dim("evidence:")} ${f.evidence}\n` +
        `   ${dim("fix:")}      ${f.recommendation}\n` +
        (f.triageNote ? `   ${dim("triage:")}   ${f.triageNote}\n` : "")
    );
  });
  out.write("\n");
}

function sev(severity: Severity, count: number): string {
  return `${SEVERITY_COLORS[severity]} ${severity}: ${count} ${RESET}`;
}
function dim(s: string): string {
  return `\x1b[90m${s}${RESET}`;
}

/** Writes report.json and report.html into the output directory. */
export function writeReports(report: ScanReport, outDir: string): { json: string; html: string } {
  fs.mkdirSync(outDir, { recursive: true });
  const jsonPath = path.join(outDir, "report.json");
  const htmlPath = path.join(outDir, "report.html");
  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2));
  fs.writeFileSync(htmlPath, renderHtml(report));
  return { json: jsonPath, html: htmlPath };
}

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderHtml(report: ScanReport): string {
  const s = report.summary;
  const rows = report.findings
    .map(
      (f, i) => `
      <tr class="sev-${f.severity}">
        <td>${i + 1}</td>
        <td><span class="badge sev-${f.severity}">${f.severity}</span></td>
        <td>${f.priority}</td>
        <td>${esc(f.title)}<div class="cat">${esc(f.category)}</div></td>
        <td class="evidence">${esc(f.evidence)}</td>
        <td>${esc(f.recommendation)}${
          f.triageNote ? `<div class="triage">Triage: ${esc(f.triageNote)}</div>` : ""
        }</td>
      </tr>`
    )
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>AuthzSwarm Report — ${esc(report.target)}</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 2rem; background: #f6f7f9; color: #1a1a1a; }
  @media (prefers-color-scheme: dark) { body { background: #14171c; color: #e6e6e6; } table { background: #1c2027; } th { background: #232833 !important; } tr:nth-child(even) td { background: #191d24; } }
  h1 { font-size: 1.4rem; margin: 0 0 .25rem; }
  .meta { color: #666; margin-bottom: 1.25rem; font-size: .85rem; }
  .summary { display: flex; gap: .5rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
  .pill { padding: .35rem .7rem; border-radius: 999px; font-weight: 600; font-size: .8rem; }
  table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
  th, td { text-align: left; padding: .6rem .75rem; vertical-align: top; border-bottom: 1px solid rgba(128,128,128,.15); font-size: .85rem; }
  th { background: #eef0f3; font-size: .75rem; text-transform: uppercase; letter-spacing: .03em; }
  td.evidence { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: .78rem; max-width: 340px; word-break: break-word; }
  .cat { color: #888; font-size: .72rem; margin-top: .2rem; }
  .triage { color: #777; font-style: italic; margin-top: .3rem; font-size: .78rem; }
  .badge { padding: .12rem .5rem; border-radius: 4px; font-size: .72rem; font-weight: 700; text-transform: uppercase; color: #fff; }
  .sev-critical .badge, .badge.sev-critical { background: #b3123b; }
  .sev-high .badge, .badge.sev-high { background: #d64545; }
  .sev-medium .badge, .badge.sev-medium { background: #d98324; }
  .sev-low .badge, .badge.sev-low { background: #2c86c9; }
  .sev-info .badge, .badge.sev-info { background: #7a7a7a; }
  .pill.critical { background:#b3123b; color:#fff; } .pill.high { background:#d64545; color:#fff; }
  .pill.medium { background:#d98324; color:#fff; } .pill.low { background:#2c86c9; color:#fff; } .pill.info { background:#7a7a7a; color:#fff; }
  .note { margin-top: 1.5rem; padding: .75rem 1rem; border-left: 3px solid #d98324; background: rgba(217,131,36,.08); font-size: .8rem; }
</style>
</head>
<body>
  <h1>AuthzSwarm Report</h1>
  <div class="meta">
    Target: <strong>${esc(report.target)}</strong> &middot;
    Triage mode: ${esc(report.triageMode)} &middot;
    ${report.checkersRun.length} checker agents &middot;
    ${esc(report.startedAt)}
  </div>
  <div class="summary">
    <span class="pill critical">critical: ${s.critical}</span>
    <span class="pill high">high: ${s.high}</span>
    <span class="pill medium">medium: ${s.medium}</span>
    <span class="pill low">low: ${s.low}</span>
    <span class="pill info">info: ${s.info}</span>
  </div>
  ${
    report.findings.length === 0
      ? "<p>No findings.</p>"
      : `<table>
    <thead><tr><th>#</th><th>Severity</th><th>Priority</th><th>Finding</th><th>Evidence</th><th>Recommendation</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`
  }
  <div class="note">
    AUTHORIZED-USE ONLY. This report reflects an authorized defensive scan of a system the operator owns or is
    permitted to test. Do not use AuthzSwarm against systems you do not own.
  </div>
</body>
</html>`;
}
