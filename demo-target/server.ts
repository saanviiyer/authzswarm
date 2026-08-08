/**
 * BUNDLED INTENTIONALLY-VULNERABLE DEMO TARGET.
 *
 * This tiny Express app has DELIBERATE security issues so AuthzSwarm can be run
 * end-to-end, offline, against a safe local target. It binds to localhost only.
 *
 * DO NOT deploy this app or expose it to a network. It exists solely as a
 * practice target for the scanner. The demo target is on the default allowlist.
 */
import express, { Request, Response, NextFunction } from "express";

const app = express();
const PORT = Number(process.env.PORT || 3000);

// (Intentional issue) Sets an insecure session cookie: no Secure, no HttpOnly.
app.use((_req, res, next) => {
  res.setHeader("Set-Cookie", "session=demo-abc123; Path=/");
  // (Intentional issue) No security headers are set (no CSP, X-Frame-Options, etc.)
  next();
});

// Home page with a search box that (intentionally) reflects input un-encoded.
app.get("/", (req: Request, res: Response) => {
  const q = typeof req.query.q === "string" ? req.query.q : "";
  // (Intentional issue) Reflected, un-encoded user input -> reflected XSS point.
  res.setHeader("Content-Type", "text/html");
  res.send(`<!doctype html>
<html><head><title>Vulnerable Demo Shop</title></head>
<body>
  <h1>Vulnerable Demo Shop</h1>
  <form action="/search" method="get">
    <input name="q" placeholder="search products" />
    <button>Search</button>
  </form>
  <p>You searched for: ${q}</p>
</body></html>`);
});

// Search endpoint: also reflects the query parameter un-encoded.
app.get("/search", (req: Request, res: Response) => {
  const q = typeof req.query.q === "string" ? req.query.q : "";
  res.setHeader("Content-Type", "text/html");
  // (Intentional issue) Reflected, un-encoded user input.
  res.send(`<!doctype html><html><body>
    <h1>Results for: ${q}</h1>
    <p>No products found.</p>
  </body></html>`);
});

// (Intentional issue) Exposed .env file.
app.get("/.env", (_req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/plain");
  res.send(
    [
      "DATABASE_URL=postgres://demo:demo@localhost:5432/shop",
      "SECRET_KEY=demo-not-a-real-secret-000",
      "STRIPE_KEY=sk_test_demo_placeholder",
    ].join("\n")
  );
});

// (Intentional issue) Exposed .git/config.
app.get("/.git/config", (_req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/plain");
  res.send(
    [
      "[core]",
      "\trepositoryformatversion = 0",
      "[remote \"origin\"]",
      "\turl = https://example.com/demo/shop.git",
    ].join("\n")
  );
});

// (Intentional issue) Open redirect: redirects to an arbitrary user-supplied URL.
app.get("/redirect", (req: Request, res: Response) => {
  const url = typeof req.query.url === "string" ? req.query.url : "/";
  res.redirect(url);
});

// (Intentional issue) Verbose error: leaks a stack trace to the client.
app.get("/error", (_req: Request, _res: Response) => {
  throw new Error("Simulated unhandled error in /error handler");
});

// (Intentional issue) Error handler that returns the full stack to the client.
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  res.status(500).setHeader("Content-Type", "text/plain");
  res.send(`Internal Server Error\n\n${err.stack}`);
});

app.listen(PORT, "127.0.0.1", () => {
  process.stdout.write(
    `Vulnerable demo target listening on http://localhost:${PORT} (localhost only)\n`
  );
});

export { app };
