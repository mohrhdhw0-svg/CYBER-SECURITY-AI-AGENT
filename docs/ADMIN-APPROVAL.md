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

Generate secrets locally with `openssl rand -hex 32`. Never commit actual secrets.

## How it works

1. A visitor submits a public IPv4 address at the engine panel.
2. The request is stored in Redis as pending. The browser receives an HttpOnly request cookie.
3. The administrator opens `/admin`, signs in, and approves or rejects the request.
4. Approval is bound to that exact IP and expires after 24 hours.
5. Approval publishes a durable `ip-scan-requests` message to Vercel Queues and returns immediately. A private queue consumer signs a per-IP HMAC permit and calls the Render engine; the engine verifies its signature, expiration, and exact IP match. Redis leases prevent concurrent duplicate deliveries from starting the same scan.
6. Private, loopback, link-local, multicast, reserved, and otherwise non-global IP addresses are rejected by both the web request validator and the engine.

The admin APIs enforce the signed session server-side; hiding the page URL is not the security boundary. Redis stores request records for seven days. Nmap remains restricted to TCP connect/service detection on at most 100 common ports, with no NSE scripts or exploit modules.

## Deployment

Deploy branch `feature/admin-approval-ip-intel` as a preview first. Configure the environment variables above in that preview and in Render, then test a request through /admin. Do not merge to main until a successful build and end-to-end approval/scan test have been completed.


## Background scan processing

The application uses Vercel Queues (public beta) with the `@vercel/queue` SDK. Enable Queues for the correct Vercel project and deploy the branch with `vercel.json`; its private `queue/v2beta` trigger subscribes the consumer route to `ip-scan-requests`. Queue publishing requires Vercel OIDC credentials supplied automatically by a Vercel deployment. Local publishing requires a linked Vercel project and pulled development credentials.

Queue delivery is at-least-once. The consumer checks the request state and acquires a short Redis lease before starting a scan. Completed, rejected, and failed requests are not re-run. The queue retries transient handler/storage failures; engine scan failures are stored as failed request results. The scan itself remains limited by the engine's public-IP authorization checks and bounded TCP service scan.

Before enabling production traffic, verify that Queues is enabled on the intended Vercel project, Redis is configured, the Render engine is reachable, and the end-to-end approval flow completes successfully. No deployment or live scan is implied by a successful source build.
