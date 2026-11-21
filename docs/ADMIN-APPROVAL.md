# Private admin approval workflow

## Required environment variables

Set these in Vercel (Production and Preview as appropriate):
- `ENGINE_URL`: the Render engine base URL.
- `ENGINE_API_TOKEN`: same bearer token configured on Render.
- `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN`: a persistent Upstash Redis database.
- `ADMIN_PANEL_PASSWORD`: a long unique admin password.
- `ADMIN_SESSION_SECRET`: a random secret of at least 32 bytes.
- `SCAN_APPROVAL_SECRET`: a random secret of at least 32 bytes.

Set these in Render:
- `ENGINE_API_TOKEN`: same value as Vercel.
- `SCAN_APPROVAL_SECRET`: exactly the same value as Vercel.
- `AUTHORIZED_CIDRS`: required comma-separated list of only the public IPs/CIDRs explicitly authorized for scanning. Leave scans disabled until the exact allowed ranges are configured; do not use documentation-only or private ranges.
- `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN`: the same persistent Upstash database configured in Vercel; required for engine-side idempotency and result replay.

Generate secrets locally with `openssl rand -hex 32`. Never commit actual secrets.

## How it works

1. A visitor submits a public IPv4 address at the engine panel.
2. The request is stored in Redis as pending. The browser receives an HttpOnly request cookie.
3. The administrator opens `/admin`, signs in, and approves or rejects the request.
4. Approval is bound to that exact IP and expires after 24 hours.
5. Approval publishes a durable `ip-scan-requests` message to Vercel Queues and returns immediately. A private queue consumer signs a per-IP HMAC permit and calls the Render engine; the engine verifies its signature, expiration, exact IP match, and request reference. Redis leases prevent concurrent app workers from starting duplicate deliveries. The engine also atomically claims the request ID in persistent Redis before scanning and stores the completed result for seven days; redelivery replays that result instead of launching Nmap again.
6. Private, loopback, link-local, multicast, reserved, and otherwise non-global IP addresses are rejected by both the web request validator and the engine.

The admin APIs enforce the signed session server-side; hiding the page URL is not the security boundary. Redis stores request records for seven days. Nmap remains restricted to TCP connect/service detection on at most 100 common ports, with no NSE scripts or exploit modules.

## Deployment

Deploy branch `feature/cyber-ai-assistant` as a preview first. Configure the environment variables above in that preview and in Render, including the mandatory `AUTHORIZED_CIDRS` allowlist, then test a request through /admin. Do not merge to main until a successful build and end-to-end approval/scan test have been completed.


## Background scan processing

The application uses Vercel Queues (public beta) with the `@vercel/queue` SDK. Enable Queues for the correct Vercel project and deploy the branch with `vercel.json`; its private `queue/v2beta` trigger subscribes the consumer route to `ip-scan-requests`. Queue publishing requires Vercel OIDC credentials supplied automatically by a Vercel deployment. Local publishing requires a linked Vercel project and pulled development credentials.

Queue delivery is at-least-once. The consumer checks the request state and acquires a short Redis lease before calling the engine. The engine's durable Redis idempotency claim is the second boundary: completed results are replayed for seven days, while a claimed execution with no persisted result is treated as uncertain and duplicate scanning is blocked. This deliberately prefers a visible failed/uncertain request over silently running the same approved scan twice. Configure the same persistent Upstash REST credentials on both Vercel and the engine. The queue retries transient handler/storage failures; engine scan failures are stored as failed request results. The scan itself remains limited by the engine's public-IP authorization checks and bounded TCP service scan.

The engine `/health` endpoint performs an authenticated Redis `PING`; a configured-but-unreachable Redis database is reported as degraded and disables scan execution. Before enabling production traffic, verify that Queues is enabled on the intended Vercel project, the same Redis database is reachable from both Vercel and Render, the Render engine is reachable, and the end-to-end approval flow completes successfully. No deployment or live scan is implied by a successful source build.
