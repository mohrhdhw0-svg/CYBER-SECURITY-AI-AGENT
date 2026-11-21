import { createHmac } from "node:crypto";

/**
 * Distributed per-IP request limit. Fails closed when Redis is unavailable.
 * @param {string} clientKey
 */
export async function checkAssistantRateLimit(clientKey) {
  const url = process.env.UPSTASH_REDIS_REST_URL?.replace(/\/$/, "");
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  const secret = process.env.ADMIN_SESSION_SECRET;
  if (!url || !token || !secret) {
    throw new Error("Assistant rate-limit storage is not configured.");
  }

  // Validate the destination before attaching the Redis bearer token.
  let redisEndpoint;
  try {
    redisEndpoint = new URL(url);
  } catch {
    throw new Error("Assistant rate-limit storage URL is invalid.");
  }
  const localDevelopmentHost = ["localhost", "127.0.0.1", "[::1]"].includes(redisEndpoint.hostname);
  const localDevelopmentHttp = process.env.NODE_ENV !== "production" &&
    redisEndpoint.protocol === "http:" && localDevelopmentHost;
  if (
    redisEndpoint.username ||
    redisEndpoint.password ||
    redisEndpoint.search ||
    redisEndpoint.hash ||
    (redisEndpoint.protocol !== "https:" && !localDevelopmentHttp)
  ) {
    throw new Error("Assistant rate-limit storage must use a valid HTTPS URL.");
  }

  const fingerprint = createHmac("sha256", secret).update(clientKey).digest("hex");
  const key = `assistant:chat:${fingerprint}`;
  const response = await fetch(redisEndpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify([
      "EVAL",
      "local count=redis.call('INCR', KEYS[1]); if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]); end; return count",
      "1",
      key,
      "600",
    ]),
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(4000),
  });

  if (!response.ok) throw new Error("Assistant rate-limit storage request failed.");
  const result = await response.json();
  if (result.error) throw new Error("Assistant rate-limit storage returned an error.");
  const count = Number(result.result);
  return {
    allowed: Number.isFinite(count) && count <= 15,
    remaining: Number.isFinite(count) ? Math.max(0, 15 - count) : 0,
  };
}
