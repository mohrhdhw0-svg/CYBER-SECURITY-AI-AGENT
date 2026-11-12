# Cloud Run pilot deployment

This is an optional deployment path for the isolated Nmap engine. It creates or updates Google Cloud Secret Manager versions and deploys the container from `./engine` to Cloud Run. It does **not** deploy automatically and does not create resources until you run the script.

## Prerequisites

- A Google Cloud project with billing enabled (Cloud Run, Cloud Build, Artifact Registry and Secret Manager may incur charges).
- Google Cloud CLI authenticated to the intended project.
- APIs enabled: Cloud Run, Cloud Build, Artifact Registry and Secret Manager.
- Permissions to deploy Cloud Run services, build source, create/update secrets, and grant Secret Manager access to the runtime service account.
- An exact lab IP/CIDR that you own or have written authorization to test. Do not use broad public ranges.
- A strong `ENGINE_API_TOKEN` (at least 32 random bytes).

## Deploy

From the repository root, run:

```bash
export GCP_PROJECT_ID="your-project-id"
export GCP_REGION="us-central1"
export ENGINE_API_TOKEN="$(openssl rand -hex 32)"
export AUTHORIZED_CIDRS="192.0.2.10/32" # Replace with your authorized lab IP/CIDR
bash engine/cloudrun/deploy.sh
```

The example CIDR is documentation-only TEST-NET space and must be replaced. The script rejects a default route (/0), validates CIDR syntax, stores the engine token and allowlist in Secret Manager, grants the Cloud Run runtime service account access to those two secrets, then deploys with 2 vCPU, 2 GiB memory, 120-second request timeout, concurrency 1, and maximum 1 instance. Minimum instances is zero to avoid idle-instance charges. Actual charges still depend on usage and Google Cloud pricing.

The service is reachable over HTTPS and uses application-level bearer authentication. Because the Vercel application currently sends a bearer token rather than a Google identity token, the script enables unauthenticated Cloud Run invocation. **Do not treat the URL as private**: the engine bearer token is the access boundary. Keep it secret, use a separate `SCAN_ACCESS_KEY` in Vercel, and never expose either value in browser code or Git.

## Connect Vercel

After deployment, set these server-side environment variables in the Vercel project:

- `ENGINE_URL`: the Cloud Run service URL printed by the script.
- `ENGINE_API_TOKEN`: exactly the same value used during deployment.
- `SCAN_ACCESS_KEY`: a separate random secret (at least 20 characters).

Redeploy the Vercel application after setting the variables. Do not paste secrets into chat, issues, commits, or screenshots.

## Verify before use

1. Open the dashboard and refresh engine status.
2. The engine must report `status=ok`, `nmap_available=true`, and `execution_enabled=true`.
3. Run a scan only against an exact target inside the configured authorized CIDR.
4. If deployment fails, inspect Cloud Run logs and IAM permissions. Do not broaden the target allowlist as a workaround.

## Pilot limitations

This is a single-instance pilot, not a durable distributed job queue or production multi-tenant scanner. Cloud Run request-based execution, cold starts, outbound networking, and service limits may affect scans. Do not add more scanners or increase concurrency until queueing, audit retention, per-user authorization, and abuse controls are implemented and tested.
