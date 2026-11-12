# Isolated Security Engine (initial)

This is a separate Docker-hosted service; it does not run inside Vercel. The first real adapter is a constrained Nmap service-discovery profile.

## Run

1. Copy `.env.example` to `.env` and set a long random `ENGINE_API_TOKEN`.
2. Replace `AUTHORIZED_CIDRS` with the exact lab IP/CIDR you own or are explicitly authorized to test. Do not use broad public ranges.
3. Build and run: `docker build -t cyber-agent-engine ./engine` then `docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=128 --memory=512m --cpus=1 -p 127.0.0.1:8080:8080 --env-file engine/.env cyber-agent-engine`.
4. Send `Authorization: Bearer <token>` to `/scans/nmap` with a literal IP, an authorization reference, and `confirm_authorized: true`.

The runner rejects targets outside `AUTHORIZED_CIDRS`, rejects hostnames, requires bearer authentication and explicit authorization confirmation, limits scans to top 10–100 TCP ports with service detection, and has a 90-second timeout. It does not invoke NSE scripts, exploit modules, password attacks, or arbitrary shell commands. Keep this API private behind a VPN or authenticated gateway; never expose it directly to the public internet. This is an initial adapter, not a full job queue or production multi-tenant service.
