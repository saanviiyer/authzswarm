# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1: build the TypeScript sources to dist/.
# ---------------------------------------------------------------------------
FROM node:20-bookworm-slim AS build
WORKDIR /app

# Install ALL deps (incl. devDependencies like typescript/tsx) without running
# lifecycle scripts. We build explicitly below, so `prepare` must not fire here
# before the sources are copied in.
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

# Bring in sources and compile.
COPY tsconfig.json ./
COPY src ./src
COPY demo-target ./demo-target
COPY scripts ./scripts
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2: slim runtime image that runs the scanner as its entrypoint.
# ---------------------------------------------------------------------------
FROM node:20-bookworm-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app

# Production dependencies only. --ignore-scripts so the `prepare` build hook
# (which needs devDependencies) does not run in the runtime image.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

# Compiled output. This already includes the compiled bundled demo target at
# dist/demo-target/server.js, so no separate TypeScript source copy is needed.
COPY --from=build /app/dist ./dist

# Default allowlist ships with ONLY localhost / 127.0.0.1 / the bundled demo
# target. The allowlist gate is fully enforced inside the container: any host
# not listed here is hard-refused before a single request is sent. Operators
# MUST mount or bake in their OWN authorized-targets.json to scan their own
# hosts, e.g.:
#
#   docker run --rm \
#     -v "$(pwd)/authorized-targets.json:/app/authorized-targets.json:ro" \
#     -v "$(pwd)/reports:/app/reports" \
#     authzswarm scan https://staging.myapp.example.com --i-am-authorized
#
# Because the container is non-interactive (no TTY), the one-time authorization
# acknowledgement must be supplied via --i-am-authorized.
COPY authorized-targets.json ./authorized-targets.json

# Reports are written under /app/reports; make it writable by the unprivileged
# user (operators can also bind-mount a host directory over it).
RUN mkdir -p /app/reports && chown -R node:node /app

# Run as the built-in unprivileged node user.
USER node

ENTRYPOINT ["node", "dist/src/cli.js"]
CMD ["--help"]
