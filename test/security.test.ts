import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import test from "node:test";
import { assertAuthorized, isPrivateNetworkAuthorized, AllowlistError } from "../src/allowlist";
import { hasAcknowledged, recordAcknowledgement } from "../src/ack";
import { ThrottledHttpClient, isNonPublicAddress } from "../src/http";
import { redactText } from "../src/redact";

test("allowlist accepts an exact authorized origin and rejects unsafe target forms", () => {
  assert.equal(assertAuthorized("https://app.example.com", ["app.example.com"]), "https://app.example.com");
  assert.equal(assertAuthorized("https://staging.internal", ["private:staging.internal"]), "https://staging.internal");
  assert.equal(isPrivateNetworkAuthorized("https://staging.internal", ["private:staging.internal"]), true);
  for (const target of ["file:///etc/passwd", "https://user:pass@app.example.com", "https://app.example.com/admin",
    "https://app.example.com?next=x", "https://app.example.com.evil.test"])
    assert.throws(() => assertAuthorized(target, ["app.example.com"]), AllowlistError);
});

test("authorization acknowledgement is bound to target and allowlist contents", () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "authzswarm-ack-"));
  try {
    recordAcknowledgement("https://one.example", ["one.example"], cwd);
    assert.equal(hasAcknowledged("https://one.example", ["one.example"], cwd), true);
    assert.equal(hasAcknowledged("https://two.example", ["one.example", "two.example"], cwd), false);
    assert.equal(fs.statSync(path.join(cwd, ".authzswarm-ack.json")).mode & 0o777, 0o600);
  } finally { fs.rmSync(cwd, { recursive: true, force: true }); }
});

test("network ranges and evidence secrets are recognized", () => {
  for (const ip of ["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.1.2", "::1", "fd00::1", "::ffff:172.16.0.1", "203.0.113.1"])
    assert.equal(isNonPublicAddress(ip), true, ip);
  assert.equal(isNonPublicAddress("8.8.8.8"), false);
  const redacted = redactText("Set-Cookie: session=abc123; token=hunter2&x=1 Authorization: Bearer abc.def");
  assert.doesNotMatch(redacted, /abc123|hunter2|abc\.def/);
});

test("HTTP client never follows a cross-origin redirect and manual mode remains observable", async () => {
  const server = http.createServer((req, res) => {
    if (req.url === "/redirect") { res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data" }); res.end(); return; }
    res.end("ok");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const client = new ThrottledHttpClient(`http://127.0.0.1:${address.port}`, { minDelayMs: 50 });
  try {
    const manual = await client.get("/redirect", { manualRedirect: true });
    assert.equal(manual.status, 302);
    await assert.rejects(() => client.get("/redirect"), /outside authorized origin/);
    await assert.rejects(() => client.get("http://169.254.169.254/"), /out-of-scope/);
  } finally {
    client.close();
    await new Promise<void>((resolve, reject) => server.close((err) => err ? reject(err) : resolve()));
  }
});
