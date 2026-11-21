import test from "node:test";
import assert from "node:assert/strict";
import { checkAssistantRateLimit } from "../app/lib/assistant-rate-limit-impl.js";

const envKeys = ["UPSTASH_REDIS_REST_URL", "UPSTASH_REDIS_REST_TOKEN", "ADMIN_SESSION_SECRET"];

function setTestEnvironment() {
  const previous = Object.fromEntries(envKeys.map((key) => [key, process.env[key]]));
  process.env.UPSTASH_REDIS_REST_URL = "https://redis.example";
  process.env.UPSTASH_REDIS_REST_TOKEN = "test-token";
  process.env.ADMIN_SESSION_SECRET = "test-secret";
  return () => {
    for (const key of envKeys) {
      if (previous[key] === undefined) delete process.env[key];
      else process.env[key] = previous[key];
    }
  };
}

test("fails closed when Redis configuration is missing", async () => {
  const restore = setTestEnvironment();
  delete process.env.UPSTASH_REDIS_REST_TOKEN;
  try {
    await assert.rejects(checkAssistantRateLimit("203.0.113.10"), /not configured/);
  } finally {
    restore();
  }
});

test("allows the fifteenth request and blocks the sixteenth", async () => {
  const restore = setTestEnvironment();
  const originalFetch = globalThis.fetch;
  let count = 14;
  globalThis.fetch = async (_url, init) => {
    assert.equal(init.method, "POST");
    assert.equal(init.cache, "no-store");
    assert.equal(init.redirect, "error");
    assert.equal(init.headers.Authorization, "Bearer test-token");
    const command = JSON.parse(init.body);
    assert.equal(command[0], "EVAL");
    assert.equal(command[4], "600");
    return Response.json({ result: ++count });
  };
  try {
    assert.deepEqual(await checkAssistantRateLimit("203.0.113.10"), { allowed: true, remaining: 0 });
    assert.deepEqual(await checkAssistantRateLimit("203.0.113.10"), { allowed: false, remaining: 0 });
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});

test("fails closed when Redis returns an HTTP error", async () => {
  const restore = setTestEnvironment();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response("unavailable", { status: 503 });
  try {
    await assert.rejects(checkAssistantRateLimit("203.0.113.10"), /request failed/);
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});

test("fails closed when Redis reports a command error", async () => {
  const restore = setTestEnvironment();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ error: "ERR command failed" });
  try {
    await assert.rejects(checkAssistantRateLimit("203.0.113.10"), /returned an error/);
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});

test("fails closed when Redis returns a malformed or unsafe counter", async (t) => {
  const restore = setTestEnvironment();
  const originalFetch = globalThis.fetch;
  try {
    for (const invalidCounter of ["not-a-number", null, "1", 0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
      await t.test(`rejects counter ${String(invalidCounter)}`, async () => {
        globalThis.fetch = async () => Response.json({ result: invalidCounter });
        await assert.rejects(
          checkAssistantRateLimit("203.0.113.10"),
          /invalid counter/,
        );
      });
    }
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});


test("rejects non-HTTPS Redis endpoints in production before sending credentials", async () => {
  const restore = setTestEnvironment();
  const previousNodeEnv = process.env.NODE_ENV;
  const originalFetch = globalThis.fetch;
  process.env.NODE_ENV = "production";
  process.env.UPSTASH_REDIS_REST_URL = "http://redis.example";
  let called = false;
  globalThis.fetch = async () => { called = true; return Response.json({ result: 1 }); };
  try {
    await assert.rejects(checkAssistantRateLimit("203.0.113.10"), /must use a valid HTTPS URL/);
    assert.equal(called, false);
  } finally {
    globalThis.fetch = originalFetch;
    if (previousNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previousNodeEnv;
    restore();
  }
});

test("rejects Redis URLs containing embedded credentials or query parameters", async () => {
  const restore = setTestEnvironment();
  const originalFetch = globalThis.fetch;
  let called = false;
  globalThis.fetch = async () => { called = true; return Response.json({ result: 1 }); };
  try {
    for (const invalidUrl of [
      "https://user:password@redis.example",
      "https://redis.example?redirect=https://attacker.example",
      "https://redis.example#fragment",
    ]) {
      process.env.UPSTASH_REDIS_REST_URL = invalidUrl;
      await assert.rejects(checkAssistantRateLimit("203.0.113.10"), /must use a valid HTTPS URL/);
    }
    assert.equal(called, false);
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});

test("cancels Redis HTTP error response bodies before failing closed", async () => {
  const restore = setTestEnvironment();
  const originalFetch = globalThis.fetch;
  let cancelled = false;
  globalThis.fetch = async () => new Response(new ReadableStream({
    cancel() { cancelled = true; },
  }), { status: 503 });
  try {
    await assert.rejects(checkAssistantRateLimit("203.0.113.10"), /request failed/);
    assert.equal(cancelled, true);
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});
