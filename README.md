# AuthzSwarm

> Runs a swarm of security checks against your own apps and reports the bugs it finds.


A multi-agent, **authorized-defensive-security** testing harness. Point it at an
application **you own** to find common web vulnerabilities before an attacker
does. It coordinates a swarm of specialized checker agents — each probing one
class of well-known issue — against an authorized target, then produces a
consolidated, ranked findings report in the terminal, as `report.json`, and as a
readable `report.html`.

Think of it as a personal DAST / pentest orchestrator: **detect-and-report, not
exploit.**

---

> ## ⚠️ AUTHORIZED-USE ONLY
>
> **Only run AuthzSwarm against systems you OWN or are EXPLICITLY AUTHORIZED to
> test. Do not use it on systems you do not own.** Scanning systems without
> permission may be illegal. AuthzSwarm enforces this in code: it refuses to scan
> any host that is not on your `authorized-targets.json` allowlist, and it
> requires a one-time authorization acknowledgement before it will run.

---

## What it checks

Each checker is an independent agent probing one class of **common, well-known**
web issue. They **detect and report** — no exploit payloads, no brute-forcing,
no credential stuffing, nothing designed to damage or persist.

| Agent | Looks for |
|---|---|
| `security-headers` | Missing CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS |
| `cookie-flags` | Cookies set without `Secure` / `HttpOnly` |
| `reflected-input` | Reflected, un-encoded input points (reflected-XSS precondition) via a benign marker |
| `exposed-paths` | Exposed `.env`, `.git/config`, backup archives, credentials, config files |
| `directory-listing` | Auto-generated directory index pages |
| `tls-basics` | Plaintext HTTP, HTTPS without HSTS |
| `verbose-errors` | Stack traces / tracebacks / SQL errors / filesystem paths leaked in error responses |
| `open-redirect` | Redirect parameters that send users to an arbitrary external URL (benign sentinel, redirect not followed) |

## How the safety controls work

1. **Allowlist gate.** AuthzSwarm reads `authorized-targets.json` and **hard-refuses**
   any target whose host is not listed. The shipped default contains only
   `localhost` / `127.0.0.1` / the bundled demo target. A host matches by
   hostname, or by `hostname:port` for a port-specific grant. You maintain this
   file.

2. **Authorization acknowledgement.** On the first run you must confirm you own
   or are authorized to test the target — either interactively, or with the
   `--i-am-authorized` flag. The confirmation is recorded once in
   `.authzswarm-ack.json`.

3. **Rate limiting / politeness.** The HTTP client throttles itself: a low
   default concurrency (2 in-flight requests) and a minimum delay between
   requests (250ms). These brakes keep it well below anything resembling a
   denial-of-service. You can raise them with `--concurrency` / `--delay` — doing
   so is your responsibility, on systems you own.

## Requirements

- Node.js 20+ (uses the built-in global `fetch`)

## Install

> **Whichever way you install it, the safety controls travel with it.** The
> allowlist gate, the one-time authorization acknowledgement, the polite
> throttling, and the detect-and-report-only scope are enforced in code and are
> identical for a local checkout, a global install, and the Docker image. A
> globally-installed or containerized AuthzSwarm still hard-refuses any host that
> is not on **your** `authorized-targets.json`.

### From source (local checkout)

```bash
npm install        # installs deps and builds dist/ via the prepare hook
npm run build      # (re)compile TypeScript -> dist/ if needed
```

### Global CLI (`authzswarm` on your PATH)

Install the compiled CLI globally so you can run `authzswarm` from anywhere:

```bash
# from inside the repo
npm install -g .        # or: npm link   (symlinks it for local development)

authzswarm --help
authzswarm scan http://localhost:3000 --i-am-authorized
```

`npm install -g .` builds `dist/` (via the `prepare` hook) and puts an
`authzswarm` executable on your PATH. The published package's `files` field ships
only `dist/`, the bundled `demo-target/`, the default `authorized-targets.json`,
this README, and `.env.example`.

**Important:** the allowlist and the acknowledgement record are read from your
**current working directory**. When you run the global CLI from your own
project, keep an `authorized-targets.json` there listing ONLY hosts you own or
are authorized to test. If none is found, AuthzSwarm refuses to run.

### Docker

A multi-stage `Dockerfile` builds the TypeScript in a full Node image and runs
the scanner from a slim runtime image. The scanner is the container entrypoint.

```bash
# Build the image
docker build -t authzswarm .

# Show help (default command)
docker run --rm authzswarm

# Scan the bundled demo target from inside the container.
# (host.docker.internal reaches a demo target running on your host)
docker run --rm authzswarm scan http://host.docker.internal:3000 --i-am-authorized
```

The image ships the **default** `authorized-targets.json`, which allows **only**
`localhost` / `127.0.0.1` / the bundled demo target. **The allowlist gate is
fully enforced inside the container** — any host not on the mounted allowlist is
hard-refused before a single request is sent. To scan your own hosts, mount your
own allowlist (and a reports volume) over the defaults:

```bash
docker run --rm \
  -v "$(pwd)/authorized-targets.json:/app/authorized-targets.json:ro" \
  -v "$(pwd)/reports:/app/reports" \
  authzswarm scan https://staging.myapp.example.com --i-am-authorized
```

Because the container is non-interactive (no TTY), the one-time authorization
acknowledgement cannot be prompted for — pass `--i-am-authorized` to confirm you
own or are explicitly authorized to test the allowlisted target(s).

## Run the demo (end-to-end, offline)

The repo bundles a tiny, intentionally-vulnerable Express app in `demo-target/`
(missing headers, an insecure cookie, reflected params, exposed `/.env` and
`/.git/config`, an open redirect, verbose errors). It binds to `localhost` only
and is on the default allowlist.

**One command — starts the target, scans it, prints the report, shuts down:**

```bash
npm run demo
```

**Or run the two halves yourself:**

```bash
# Terminal 1: start the vulnerable demo target
npm run demo:target

# Terminal 2: scan it
npm run scan -- http://localhost:3000 --i-am-authorized
```

Either way you get a ranked report in the terminal plus `report.json` and
`report.html` under `reports/`.

## Build

```bash
npm run build      # tsc -> dist/
node dist/src/cli.js scan http://localhost:3000 --i-am-authorized
```

## Point it at your own app

1. Add your host to `authorized-targets.json` — **only** hosts you own or are
   authorized to test:

   ```json
   {
     "allowedTargets": ["localhost", "staging.myapp.example.com"]
   }
   ```

2. Run the scan:

   ```bash
   npm run scan -- https://staging.myapp.example.com --i-am-authorized
   ```

If you point it at a host that is not on the allowlist, it refuses:

```
REFUSING TO SCAN: "example.com" is not on the allowlist.
```

## CLI options

```
authzswarm scan <target-url> [options]

  --i-am-authorized     Confirm authorization (recorded once)
  --concurrency <n>     Max concurrent requests (default 2)
  --delay <ms>          Min delay between requests (default 250)
  --timeout <ms>        Per-request timeout (default 10000)
  --no-triage           Skip the triage/prioritization step
  --out <dir>           Output directory for report.json / report.html
```

The process exits non-zero when any `high` or `critical` finding is present, so
you can gate CI on it.

## LLM-assisted triage (optional)

After aggregating findings, AuthzSwarm can use Claude to summarize and
re-prioritize them.

- **With a key:** copy `.env.example` to `.env` and set `ANTHROPIC_API_KEY`.
  Triage uses `claude-sonnet-5` (override with `AUTHZSWARM_TRIAGE_MODEL`). The
  `ANTHROPIC_API_KEY` environment variable is read automatically.
- **Without a key (MOCK MODE):** triage falls back to deterministic
  severity-based prioritization, so the tool runs end-to-end with zero setup.

Triage never drops a finding — any gap in the model's response is backfilled from
the deterministic scoring.

## Output

- **Terminal:** colorized, severity-ranked findings.
- **`report.json`:** full structured report (target, timings, checkers run,
  triage mode, per-severity summary, all findings with priority + triage notes).
- **`report.html`:** a shareable, theme-aware HTML table of the same.

## Project layout

```
authzswarm/
  authorized-targets.json   # the allowlist (localhost + demo only by default)
  src/
    cli.ts                  # entry point + arg parsing
    allowlist.ts            # allowlist gate (hard refuse)
    ack.ts                  # authorization acknowledgement
    http.ts                 # throttled, polite HTTP client
    orchestrator.ts         # fan-out, aggregate/dedupe, triage, rank
    triage.ts               # Claude-assisted triage w/ mock fallback
    report.ts               # terminal + JSON + HTML reports
    types.ts                # shared types
    checkers/               # one module per issue class (the swarm)
  demo-target/
    server.ts               # bundled intentionally-vulnerable Express app
  scripts/
    demo.ts                 # one-command demo runner
```

## Scope & non-goals

AuthzSwarm probes for common, well-known issue classes and reports them. It does
**not** implement exploit payloads, credential stuffing, brute-forcing, or
anything designed to damage or persist. It is defensive tooling for use on your
own systems.
