# Isolated Security Engine (initial)

This is a separate Docker-hosted service; it does not run inside Vercel. The first real adapter is a constrained Nmap service-discovery profile.

## Run

1. Copy `engine/.env.example` to `engine/.env` and set a long random `ENGINE_API_TOKEN` (at least 32 random bytes).
2. Replace `AUTHORIZED_CIDRS` with the exact lab IP/CIDR you own or are explicitly authorized to test. Do not use broad public ranges.
3. After the `Build and publish isolated scanner engine` GitHub Actions workflow succeeds, authenticate the host to GHCR with a token that has `read:packages`, then run `docker compose pull && docker compose up -d`. For a local build instead, run `docker compose up -d --build`.
4. The Compose service pulls `ghcr.io/mohrhdhw0-svg/cyber-security-ai-agent-engine:latest` (or builds locally) and binds to 127.0.0.1 only. Vercel hosts the Next.js dashboard, not this persistent Docker scanner. Run the engine on a separate VPS or private server. Put it behind a VPN or authenticated HTTPS reverse proxy that permits requests only from your app/server; do not expose port 8080 directly. Configure Vercel server-side variables `ENGINE_URL` (the restricted HTTPS endpoint), `ENGINE_API_TOKEN` (the same random token configured on the engine), and `SCAN_ACCESS_KEY` (a separate random secret of at least 20 characters). The dashboard requires this access key before submitting a scan. Never commit these values.
5. Send `Authorization: Bearer <token>` to `/scans/nmap` with a literal IP, an authorization reference, and `confirm_authorized: true`.

The runner rejects targets outside `AUTHORIZED_CIDRS`, rejects hostnames, requires bearer authentication and explicit authorization confirmation. Health and tool metadata endpoints also require bearer authentication, limits scans to top 10–100 TCP ports with service detection, and has a 90-second timeout. It does not invoke NSE scripts, exploit modules, password attacks, or arbitrary shell commands. Keep this API private behind a VPN or authenticated gateway; never expose it directly to the public internet. This is an initial adapter, not a full job queue or production multi-tenant service.


## Image publication

A push that changes `engine/**` starts `.github/workflows/engine-image.yml`. The workflow builds the image and publishes `latest` and the commit-SHA tag to GitHub Container Registry (GHCR). Confirm the workflow completed successfully and the package is visible before pulling it on the VPS. If the package is private, authenticate the VPS with a GitHub token that has `read:packages`.
