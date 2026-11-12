#!/usr/bin/env bash
set -Eeuo pipefail

: "${GCP_PROJECT_ID:?Set GCP_PROJECT_ID to your Google Cloud project ID}"
: "${ENGINE_API_TOKEN:?Set ENGINE_API_TOKEN to a long random secret (at least 32 bytes)}"
: "${AUTHORIZED_CIDRS:?Set AUTHORIZED_CIDRS to the exact lab IP/CIDR you are authorized to test}"

GCP_REGION="${GCP_REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-cyber-security-ai-agent-engine}"
RUNTIME_SERVICE_ACCOUNT="${RUNTIME_SERVICE_ACCOUNT:-}"

command -v gcloud >/dev/null || { echo "gcloud CLI is required." >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required to validate CIDRs." >&2; exit 1; }

python3 - "$AUTHORIZED_CIDRS" <<'PY'
import ipaddress, sys
items = [x.strip() for x in sys.argv[1].split(",") if x.strip()]
if not items:
    raise SystemExit("AUTHORIZED_CIDRS cannot be empty")
for item in items:
    net = ipaddress.ip_network(item, strict=False)
    if net.prefixlen == 0:
        raise SystemExit("Refusing a /0 allowlist.")
    if net.is_multicast or net.is_unspecified:
        raise SystemExit(f"Refusing unsafe network: {item}")
print("CIDR allowlist syntax validated.")
PY

gcloud config set project "$GCP_PROJECT_ID" >/dev/null

ensure_secret() {
  local name="$1"
  if ! gcloud secrets describe "$name" --project "$GCP_PROJECT_ID" >/dev/null 2>&1; then
    gcloud secrets create "$name" --replication-policy=automatic --project "$GCP_PROJECT_ID"
  fi
}

ensure_secret "cyber-engine-api-token"
ensure_secret "cyber-engine-authorized-cidrs"
printf '%s' "$ENGINE_API_TOKEN" | gcloud secrets versions add cyber-engine-api-token --data-file=- --project "$GCP_PROJECT_ID"
printf '%s' "$AUTHORIZED_CIDRS" | gcloud secrets versions add cyber-engine-authorized-cidrs --data-file=- --project "$GCP_PROJECT_ID"

if [[ -z "$RUNTIME_SERVICE_ACCOUNT" ]]; then
  PROJECT_NUMBER="$(gcloud projects describe "$GCP_PROJECT_ID" --format='value(projectNumber)')"
  RUNTIME_SERVICE_ACCOUNT="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
fi

for secret in cyber-engine-api-token cyber-engine-authorized-cidrs; do
  gcloud secrets add-iam-policy-binding "$secret" \
    --member="serviceAccount:$RUNTIME_SERVICE_ACCOUNT" \
    --role="roles/secretmanager.secretAccessor" \
    --project "$GCP_PROJECT_ID" >/dev/null
done

gcloud run deploy "$SERVICE_NAME" \
  --source ./engine \
  --region "$GCP_REGION" \
  --platform managed \
  --execution-environment gen2 \
  --service-account "$RUNTIME_SERVICE_ACCOUNT" \
  --allow-unauthenticated \
  --port 8080 \
  --cpu 2 \
  --memory 2Gi \
  --timeout 120 \
  --concurrency 1 \
  --min 0 \
  --max 1 \
  --set-secrets "ENGINE_API_TOKEN=cyber-engine-api-token:latest,AUTHORIZED_CIDRS=cyber-engine-authorized-cidrs:latest" \
  --quiet

SERVICE_URL="$(gcloud run services describe "$SERVICE_NAME" --region "$GCP_REGION" --format='value(status.url)')"
printf '\nDeployment command completed. Service URL: %s\n' "$SERVICE_URL"
printf 'Set ENGINE_URL to this URL in Vercel. Set ENGINE_API_TOKEN to the same secret and create a separate SCAN_ACCESS_KEY.\n'
printf 'Do not enable scans until the service health endpoint reports execution_enabled=true.\n'
