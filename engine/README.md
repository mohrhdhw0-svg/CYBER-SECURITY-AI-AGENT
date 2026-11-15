# Isolated Security Engine

This Docker-hosted service runs separately from Vercel. The current adapter performs passive public-IP intelligence lookups and a bounded Nmap TCP/service scan. Every scan requires a short-lived, signed approval permit issued by the private admin workflow.

## Required engine environment

- `ENGINE_API_TOKEN`: long random bearer token shared with the Vercel server environment.
- `SCAN_APPROVAL_SECRET`: long random HMAC secret shared with Vercel; it must match exactly.
- `AUTHORIZED_CIDRS` (optional): comma-separated additional IP/CIDR restrictions. These restrictions can narrow which approved targets are accepted, but they never replace or bypass the per-request admin approval permit.
- `ABUSEIPDB_API_KEY` (optional): enables reputation enrichment.

Never commit real credentials. Configure the engine variables in the Docker host/Render service and the matching Vercel variables in the intended Vercel project.

## Run

1. Build and start the service using the repository's Docker Compose configuration or the published GHCR image.
2. Keep the engine behind a private network, VPN, or authenticated HTTPS reverse proxy. Do not expose port 8080 directly to the public internet.
3. Set Vercel `ENGINE_URL` to the restricted HTTPS endpoint and `ENGINE_API_TOKEN` / `SCAN_APPROVAL_SECRET` to the matching secrets.
4. Configure the Vercel approval workflow's Redis and admin-session environment variables as documented in `docs/ADMIN-APPROVAL.md`.

## Authorization and scan limits

- The engine requires a valid bearer token.
- Every scan requires a short-lived HMAC permit bound to the exact public IP and approval expiry.
- Private, loopback, link-local, multicast, reserved, and otherwise non-global IP addresses are rejected.
- If `AUTHORIZED_CIDRS` is configured, the target must also fall inside one of those additional ranges.
- Nmap is limited to the top 10–100 common TCP ports, conservative timing, service detection, and a bounded timeout.
- No exploit attempts, credential attacks, arbitrary shell commands, or intrusive NSE scripts are run.

The engine's health and tool metadata endpoints also require bearer authentication. A successful application build does not by itself prove that the external engine, Redis, queue subscription, or end-to-end approval flow is operational.
