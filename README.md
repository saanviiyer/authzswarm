# authzswarm

AuthzSwarm runs a set of security checks against web apps you own and reports the common bugs it finds. It is a defensive testing tool. It detects and reports issues. It does not exploit them.

> **Authorized use only.** Run AuthzSwarm only against systems you own or have explicit permission to test. Do not use it on systems you do not own. Scanning systems without permission may be illegal. The code enforces this rule. It refuses any host that is not in your `authorized-targets.json` allowlist, and it requires an authorization acknowledgement before it runs.

## What it checks

Each checker probes one class of common, well-known web issue. The checkers send no exploit payloads. They do no brute-forcing or credential stuffing, and they do nothing designed to damage or persist.

| Checker | Looks for |
|---|---|
| `security-headers` | Missing CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS |
| `cookie-flags` | Cookies set without `Secure` or `HttpOnly` |
| `reflected-input` | Reflected, unencoded input (a reflected-XSS precondition), found with a benign marker |
| `exposed-paths` | Exposed `.env`, `.git/config`, backup archives, credentials, config files |
| `directory-listing` | Auto-generated directory index pages |
| `tls-basics` | Plaintext HTTP, and HTTPS without HSTS |
| `verbose-errors` | Stack traces, SQL errors or filesystem paths in error responses |
| `open-redirect` | Redirect parameters that send users to any external URL (benign sentinel, redirect not followed) |

The tool merges and ranks the findings. It prints them in the terminal and writes `report.json` and `report.html` to `reports/scan-<timestamp>/`.

## Safety controls

1. **Allowlist gate.** The tool reads `authorized-targets.json` and refuses any host that is not listed. The default file lists only `localhost`, `127.0.0.1` and the bundled demo target. An entry matches a hostname, or `hostname:port` for a port-specific grant. You maintain this file.
2. **Authorization acknowledgement.** You confirm that you own or may test the target, either at an interactive prompt or with `--i-am-authorized`. The record is bound to that origin and to a digest of the current allowlist. A change to either one asks for confirmation again. The tool writes the record atomically with owner-only permissions.
3. **Network containment.** All requests stay on the authorized origin. The tool never follows redirects to another origin. It resolves DNS once and pins the result for the scan to prevent rebinding. It caps response body size and redirect depth. It rejects non-public DNS results unless you gave the target as localhost or an IP literal, or added a `private:` grant for it.
4. **Rate limits.** The HTTP client uses 2 concurrent requests and a 250 ms minimum delay by default. It allows at most 8 concurrent requests and at most 100 requests per scan. Delay and timeout inputs have hard bounds.
5. **Redacted reports.** The tool redacts common credentials, cookie values and sensitive query parameters before terminal output, report files or LLM triage. If a checker fails, the tool marks the scan incomplete and exits non-zero. It does not report a false clean result.

These controls apply the same way to a local checkout, a global install and the Docker image.

## Run it

You need Node.js 20 or later.

```bash
git clone https://github.com/saanviiyer/authzswarm
cd authzswarm
npm install        # also builds dist/ through the prepare hook
npm test
```

### Demo

The `demo-target/` folder holds a small Express app with known issues on purpose. It listens on `127.0.0.1` only and is on the default allowlist.

```bash
npm run demo       # starts the target, scans it, prints the report, stops
```

To run the two parts yourself, start `npm run demo:target` in one terminal. Then run `npm run scan -- http://localhost:3000 --i-am-authorized` in a second terminal.

### Scan your own app

Add only hosts you own or may test to `authorized-targets.json`:

```json
{
  "allowedTargets": ["localhost", "staging.myapp.example.com"]
}
```

For an authorized internal hostname that resolves to a private address, add an entry such as `"private:staging.internal.example:8443"`. This grant applies to that hostname and port only. It does not weaken the redirect or DNS pinning controls.

```bash
npm run scan -- https://staging.myapp.example.com --i-am-authorized
```

For a host that is not on the allowlist, the tool prints `REFUSING TO SCAN: "example.com" is not on the allowlist.` and sends no requests.

### CLI options

```
authzswarm scan <target-url> [options]

  --i-am-authorized     Confirm authorization (recorded once)
  --concurrency <n>     Max concurrent requests (default 2)
  --delay <ms>          Min delay between requests (default 250)
  --timeout <ms>        Per-request timeout (default 10000)
  --no-triage           Skip the triage step
  --out <dir>           Output directory (default reports/scan-<timestamp>)
```

The process exits non-zero when it finds a `high` or `critical` issue, or when a checker fails. You can use this exit code to gate CI.

### Global install

```bash
npm install -g .   # or: npm link
authzswarm scan http://localhost:3000 --i-am-authorized
```

The global CLI reads the allowlist and the acknowledgement record from the current working directory. Keep an `authorized-targets.json` in your project that lists only hosts you own or may test. If the tool finds no allowlist, it refuses to run.

### Docker

```bash
docker build -t authzswarm .
docker run --rm authzswarm scan http://host.docker.internal:3000 --i-am-authorized
```

The image ships the default allowlist, and the allowlist gate works inside the container. To scan your own hosts, mount your own allowlist and a reports folder:

```bash
docker run --rm \
  -v "$(pwd)/authorized-targets.json:/app/authorized-targets.json:ro" \
  -v "$(pwd)/reports:/app/reports" \
  authzswarm scan https://staging.myapp.example.com --i-am-authorized
```

The container has no TTY and cannot show the prompt. Pass `--i-am-authorized` to confirm that you own or may test the allowlisted targets.

## Environment variables

Copy `.env.example` to `.env`. The tool runs without any of these. With no API key, triage uses deterministic severity-based ranking (mock mode).

| Name | Required | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | Optional | Turns on Claude triage of findings |
| `AUTHZSWARM_TRIAGE_MODEL` | Optional | Model for triage (default `claude-sonnet-5`) |
| `PORT` | Optional | Port for the demo target and demo script (default 3000) |

Triage never drops a finding. If the model response leaves a gap, the tool fills it from the deterministic scores.

## Layout

```
authorized-targets.json   allowlist (localhost and demo only by default)
src/cli.ts                entry point and argument parsing
src/allowlist.ts          allowlist gate
src/ack.ts                authorization acknowledgement
src/http.ts               throttled HTTP client
src/redact.ts             redaction of secrets in output
src/orchestrator.ts       runs checkers, merges and ranks findings
src/triage.ts             Claude triage with mock fallback
src/report.ts             terminal, JSON and HTML reports
src/checkers/             one module per issue class
demo-target/server.ts     demo Express app with known issues
scripts/demo.ts           one-command demo runner
test/                     security tests
```

License: MIT (see `package.json`).
