# Production architecture and deployment path

## Decision

Keep the Next.js control plane on Vercel. Run scanners as separate, bounded worker services. Never run scanners inside a Next.js request process and never accept arbitrary shell commands from the browser.

The first supported execution adapter is Nmap in engine/. The engine is a constrained FastAPI service. It requires a bearer token, an explicit authorization confirmation, a literal IP target, and membership in the operator-configured AUTHORIZED_CIDRS allowlist.

## Cloud Run evaluation

Cloud Run is a candidate for the first managed container deployment because it runs OCI containers and can scale to zero. It is not a universal replacement for persistent compute:
- scale-to-zero introduces cold starts;
- request timeout and instance concurrency must be configured for bounded jobs;
- outbound network reachability depends on the target network and Cloud Run networking configuration;
- long-running or high-volume scans should move to a dedicated worker pool and queue;
- costs can occur when resources are used. Set billing alerts and maximum instance limits before production.

Do not deploy until a billing account, region, service name, and authorized target CIDR are intentionally selected. The repository does not contain cloud credentials and must never store them.

## Initial Cloud Run sizing (pilot only)

Use a pilot service with 2 vCPU, 2 GiB memory, request timeout 120 seconds, concurrency 1, and maximum instances 1. These are conservative starting limits, not a performance guarantee. Keep ingress HTTPS-only and protect the service with a long random ENGINE_API_TOKEN. Set AUTHORIZED_CIDRS to the exact lab address/range. Do not use broad public ranges.

The Vercel application needs server-side secrets:
- ENGINE_URL: HTTPS Cloud Run service URL;
- ENGINE_API_TOKEN: same random token configured on the engine;
- SCAN_ACCESS_KEY: separate random secret used by the dashboard API.

Never use NEXT_PUBLIC_ prefixes for these values. Never commit them to Git.

## Why there is no all-tools-enabled switch

Each tool has distinct operating-system, network, licensing, storage, and runtime requirements. Tools will be integrated as independent adapters with explicit states: planned, configured, healthy, and tested. A catalog entry is not a working integration.

## Next milestones

1. Validate Nmap engine behavior and authorization boundaries in CI.
2. Add an asynchronous job queue and worker status model.
3. Add persistent PostgreSQL storage for assets, approvals, jobs, findings, and audit events.
4. Add object storage for reports and evidence.
5. Integrate ZAP, Nuclei, Trivy, YARA, and other tools as separately versioned adapters.
6. Add AI-assisted triage and remediation suggestions. AI must not silently authorize or launch scans.

## Safety requirements

- Written authorization and exact scope are required.
- Reject targets outside the configured allowlist.
- Use non-privileged containers, least privilege, resource limits, and timeouts.
- Do not expose Docker sockets or arbitrary command execution.
- Do not run password attacks, exploit modules, or destructive tests as default workflows.
