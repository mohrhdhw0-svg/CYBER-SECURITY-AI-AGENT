# Cyber AI Assistant

The dashboard includes a branded chat assistant for defensive cybersecurity education. It is an isolated feature: it does not execute scanners, invoke shell commands, access user files, or change the existing scan engine.

## Server-side configuration

Set these encrypted environment variables in the deployment environment:

- `AI_API_BASE_URL`: HTTPS base URL of an OpenAI-compatible API, including its API prefix, for example `https://your-ai-gateway.example/v1`.
- `AI_API_KEY`: the gateway's unified API key. Keep it server-side; never expose it to browser code.
- `AI_MODEL`: exact model identifier accepted by the configured gateway.
- `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`, and `ADMIN_SESSION_SECRET`: required for distributed per-IP chat rate limiting.

The server sends requests to `{AI_API_BASE_URL}/chat/completions`. FreeLLMAPI documents this OpenAI-compatible endpoint and uses `auto` as a supported model selector; its documented local default is `http://localhost:3001/v1`. For a Vercel deployment, `localhost` would refer to the Vercel runtime and is not a reachable gateway: the owner must provide a privately secured, reachable HTTPS endpoint. The gateway URL and unified key must be supplied by the project owner. The assistant route fails closed if Redis rate limiting is unavailable.

**Important deployment constraint:** FreeLLMAPI describes itself as a single-user, trusted-network tool, not a production or multi-tenant service. Do not expose its dashboard or raw gateway publicly, and do not treat one personal free-tier key as permission to serve an unrestricted public audience. Before a public launch, use an inference provider and account plan whose terms explicitly allow this application and its intended users, or implement a separately reviewed multi-tenant gateway. The MIT license permits code reuse subject to its notice requirements, but does not override upstream model-provider terms.

## Security controls

- Provider credentials are read only by the server route and are never returned by the status endpoint.
- Production provider URLs must use HTTPS; local HTTP is allowed only during non-production development.
- Provider redirects are rejected so the bearer credential is not sent through an unexpected redirect.
- On Vercel, the rate limiter prefers `x-vercel-forwarded-for`, which Vercel documents as its edge-derived client IP header. For other hosting platforms, verify that the configured proxy overwrites forwarded-IP headers before trusting them.
- Redis rate limiting fails closed if its configuration or service is unavailable.
- The Redis REST URL must use HTTPS in production (local HTTP is allowed only for non-production localhost testing); embedded URL credentials, query strings, fragments, and redirects are rejected before the Redis bearer token is sent.

## Limits and behavior

- Maximum 12 conversation messages per request.
- Maximum 6,000 characters per message.
- Maximum 100 KB request body, enforced while reading the request stream (not only from the optional `Content-Length` header).
- Maximum 1 MB upstream provider response, enforced while reading the response stream.
- 15 requests per IP per 10-minute window, enforced through Redis.
- 45-second provider timeout and 1,200-token response limit.
- Conversation state is held in the browser session and is not persisted to the database.
- The system prompt restricts the assistant to defensive, educational, and authorized-lab guidance.
- The chat does not have access to the platform's scanner or other tools.
- The status endpoint reports whether required settings exist; it does not prove that Redis or the AI provider is reachable or that credentials are valid.

## Deployment

Configure the variables in the Vercel project settings only after choosing a gateway that is reachable from Vercel and authorized for the intended audience. A local FreeLLMAPI address is not sufficient for Vercel. Then deploy the feature branch through a preview deployment. Do not merge into `main` until the preview and end-to-end provider test pass.

## Automated tests

Run `npm test` to execute the Node.js built-in test suite. It covers streamed request-size enforcement and UTF-8 decoding, plus provider request credential placement, redirect rejection, timeout handling, HTTP 429 handling, invalid/empty provider responses, the 1 MB response limit, and Redis rate-limit enforcement including fail-closed behavior and rejection of insecure or redirecting Redis endpoints. The branch validation workflow runs these tests before ESLint and the Next.js production build.
