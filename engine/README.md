# Isolated Security Engine

This Docker-hosted service runs separately from Vercel. The current adapter performs passive public-IP intelligence lookups and a bounded Nmap TCP/service scan. Every scan requires a short-lived, signed approval permit issued by the private admin workflow.

## Required engine environment

- `ENGINE_API_TOKEN`: long random bearer token shared with the Vercel server environment.
- `SCAN_APPROVAL_SECRET`: long random HMAC secret shared with Vercel; it must match exactly.
- `AUTHORIZED_CIDRS` (required): comma-separated public IP/CIDR allowlist. The engine refuses to enable scans when this is empty; every target must match this allowlist and also have a valid per-request admin approval permit.
- `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN` (required): persistent Upstash REST credentials. The engine uses atomic Redis claims and stores completed results for seven days so queue redelivery can replay results without launching a second Nmap process.
- `ABUSEIPDB_API_KEY` (optional): enables reputation enrichment.

Never commit real credentials. Configure the engine variables in the Docker host/Render service and the matching Vercel variables in the intended Vercel project.

## Run

1. Build and start the service using the repository's Docker Compose configuration or the published GHCR image.
2. Keep the engine behind a private network, VPN, or authenticated HTTPS reverse proxy. Do not expose port 8080 directly to the public internet.
3. Set Vercel `ENGINE_URL` to the restricted HTTPS endpoint and `ENGINE_API_TOKEN` / `SCAN_APPROVAL_SECRET` to the matching secrets.
4. Configure the Vercel approval workflow's Redis and admin-session environment variables as documented in `docs/ADMIN-APPROVAL.md`.
5. Configure the same persistent Upstash Redis REST URL/token on the engine. The engine health endpoint performs an authenticated Redis `PING`; it reports degraded and refuses scans if the database is missing or unreachable.

## Authorization and scan limits

- The engine requires a valid bearer token.
- Every scan requires a short-lived HMAC permit bound to the exact public IP, a valid request ID, the approval reference, and the approval expiry.
- Private, loopback, link-local, multicast, reserved, and otherwise non-global IP addresses are rejected.
- The `AUTHORIZED_CIDRS` allowlist is mandatory; the target must fall inside one of its explicitly authorized public ranges.
- Nmap is limited to the top 10–100 common TCP ports, conservative timing, service detection, and a bounded timeout.
- No exploit attempts, credential attacks, arbitrary shell commands, or intrusive NSE scripts are run.
- Each approved request ID is claimed atomically in Redis before work begins. The claim and cached result are bound to the target, approval reference, scan profile, and port limit, preventing a result from one scan mode being replayed for another. A completed result is persisted for seven days and replayed on duplicate delivery. If execution was interrupted after the claim but before a result was stored, the engine blocks a second scan and reports an uncertain/in-progress outcome rather than risking duplicate execution.

The engine's health and tool metadata endpoints also require bearer authentication. A successful application build does not by itself prove that the external engine, Redis, queue subscription, or end-to-end approval flow is operational.
