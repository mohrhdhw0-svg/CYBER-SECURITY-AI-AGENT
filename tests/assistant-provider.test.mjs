import test from "node:test";
import assert from "node:assert/strict";
import { fetchAssistantCompletion } from "../app/lib/assistant-provider.js";

const options = {
  endpoint: new URL("https://provider.example/v1/chat/completions"),
  apiKey: "test-only-key",
  model: "test-model",
  messages: [{ role: "user", content: "hello" }],
  systemPrompt: "test system",
};

function jsonResponse(value, init = {}) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });
}

test("sends credentials server-side and requests redirects to be rejected", async () => {
  const originalFetch = globalThis.fetch;
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return jsonResponse({ choices: [{ message: { content: "hello back" } }] });
  };
  try {
    const result = await fetchAssistantCompletion(options);
    assert.deepEqual(result, { ok: true, answer: "hello back" });
    assert.equal(captured.init.headers.Authorization, "Bearer test-only-key");
    assert.equal(captured.init.redirect, "error");
    assert.equal(captured.init.cache, "no-store");
    assert.equal(JSON.parse(captured.init.body).model, "test-model");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("joins text content parts with real newline characters", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => jsonResponse({
    choices: [{ message: { content: [
      { type: "text", text: "first line" },
      { type: "image", image_url: "ignored" },
      { type: "text", text: "second line" },
    ] } }],
  });
  try {
    assert.deepEqual(await fetchAssistantCompletion(options), {
      ok: true, answer: "first line\\nsecond line",
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("maps provider HTTP 429 to a rate-limited failure", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response("busy", { status: 429 });
  try {
    assert.deepEqual(await fetchAssistantCompletion(options), {
      ok: false, status: 502, reason: "rate_limited",
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("rejects provider redirects instead of following them", async () => {
  const originalFetch = globalThis.fetch;
  let redirectMode;
  globalThis.fetch = async (_url, init) => {
    redirectMode = init.redirect;
    throw new TypeError("redirect mode error");
  };
  try {
    const result = await fetchAssistantCompletion(options);
    assert.equal(redirectMode, "error");
    assert.deepEqual(result, { ok: false, status: 504, reason: "connection_error" });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("maps provider timeouts to a gateway timeout", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new DOMException("timed out", "TimeoutError"); };
  try {
    assert.deepEqual(await fetchAssistantCompletion({ ...options, timeoutMs: 5 }), {
      ok: false, status: 504, reason: "timeout",
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("rejects a provider response over one megabyte from Content-Length", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response("{}", {
    status: 200, headers: { "content-length": "1000001" },
  });
  try {
    assert.deepEqual(await fetchAssistantCompletion(options), {
      ok: false, status: 502, reason: "response_too_large",
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("enforces the response byte limit while streaming without Content-Length", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(600_000));
      controller.enqueue(new Uint8Array(500_000));
      controller.close();
    },
  }));
  try {
    assert.deepEqual(await fetchAssistantCompletion(options), {
      ok: false, status: 502, reason: "response_too_large",
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("rejects invalid JSON and empty provider answers", async (t) => {
  const originalFetch = globalThis.fetch;
  try {
    await t.test("invalid JSON", async () => {
      globalThis.fetch = async () => new Response("not json");
      assert.deepEqual(await fetchAssistantCompletion(options), {
        ok: false, status: 502, reason: "invalid_provider_json",
      });
    });
    await t.test("empty answer", async () => {
      globalThis.fetch = async () => jsonResponse({ choices: [{ message: { content: "  " } }] });
      assert.deepEqual(await fetchAssistantCompletion(options), {
        ok: false, status: 502, reason: "empty_answer",
      });
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});
