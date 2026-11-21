# Cyber AI Assistant

The dashboard includes a branded chat assistant for defensive cybersecurity education. It is an isolated feature: it does not execute scanners, invoke shell commands, access user files, or change the existing scan engine.

## Server-side configuration

Set these encrypted environment variables in the deployment environment:

- `AI_API_BASE_URL`: HTTPS base URL of an OpenAI-compatible API, including its API prefix, for example `https://your-ai-gateway.example/v1`.
- `AI_API_KEY`: the gateway's unified API key. Keep it server-side; never expose it to browser code.
- `AI_MODEL`: exact model identifier accepted by the configured gateway.
- `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`, and `ADMIN_SESSION_SECRET`: required for distributed per-IP chat rate limiting.

The server sends requests to `{AI_API_BASE_URL}/chat/completions`. This works with compatible gateways; the gateway URL and credentials must be supplied by the project owner. The assistant route fails closed if Redis rate limiting is unavailable.

## Limits and behavior

- Maximum 12 conversation messages per request.
- Maximum 6,000 characters per message.
- 15 requests per IP per 10-minute window, enforced through Redis.
- 45-second provider timeout and 1,200-token response limit.
- Conversation state is held in the browser session and is not persisted to the database.
- The system prompt restricts the assistant to defensive, educational, and authorized-lab guidance.
- The chat does not have access to the platform's scanner or other tools.

## Deployment

Configure the variables in the Vercel project settings, then deploy the feature branch through a preview deployment. Do not merge into `main` until the preview and end-to-end provider test pass.
